//! One proof in flight: each block the engine executes from a newPayload
//! starts a job (witness → pre-check → prove → sign → submit) and cancels
//! the previous one if it hasn't produced its proof yet.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use anyhow::{bail, Context, Result};
use futures::StreamExt;
use reth_engine_primitives::ConsensusEngineEvent;
use reth_ethereum::evm::primitives::ConfigureEvm;
use reth_ethereum::primitives::RecoveredBlock;
use reth_ethereum::provider::{HeaderProvider, StateProviderFactory};
use reth_ethereum::{Block, EthPrimitives};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::beacon::{BeaconClient, ChainParams};
use crate::precheck::Precheck;
use crate::prover::{Outcome, Prover};
use crate::signer::{self, Signer};
use crate::ssz::{ExecutionProofEnvelope, PublicInput, Root};

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    /// Build and pre-check the input only.
    Witness,
    /// Run the ELF under ziskemu (no proof): checks the public output.
    Emulate,
    /// Prove with the ZisK coordinator, sign and (with --zisk.submit) submit.
    Prove,
}

/// Signing identity and beacon-chain parameters (prove mode).
pub struct Submitter {
    pub beacon: BeaconClient,
    pub params: ChainParams,
    pub signer: Signer,
    pub validator_index: u64,
    pub proof_type: u8,
    pub submit: bool,
}

pub struct Config {
    pub mode: Mode,
    pub chain_id: u64,
    pub out_dir: PathBuf,
    pub precheck: Precheck,
    pub prover: Option<Prover>,
    pub submitter: Option<Submitter>,
}

/// Wall-clock marks of one block's job, for the per-block timing report.
#[derive(Clone, Default)]
pub struct Timeline(Arc<std::sync::Mutex<Vec<(&'static str, SystemTime)>>>);

impl Timeline {
    fn at(&self, label: &'static str, t: SystemTime) {
        self.0.lock().unwrap().push((label, t));
    }
    pub fn mark(&self, label: &'static str) {
        self.at(label, SystemTime::now());
    }
    /// `{label: ms}` relative to t0 = newPayload received (else the first
    /// mark), plus t0 itself and its offset from the slot start.
    fn report(&self, slot_start_unix: u64) -> serde_json::Value {
        let marks = self.0.lock().unwrap().clone();
        let Some(t0) = marks.iter().find(|(l, _)| *l == "newpayload_received").or(marks.first()).map(|(_, t)| *t)
        else {
            return json!({});
        };
        let ms = |t: SystemTime| -> f64 {
            match t.duration_since(t0) {
                Ok(d) => d.as_secs_f64() * 1e3,
                Err(e) => -e.duration().as_secs_f64() * 1e3,
            }
        };
        let unix_ms = |t: SystemTime| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let mut rel = serde_json::Map::new();
        for (l, t) in &marks {
            rel.insert(l.to_string(), json!((ms(*t) * 10.0).round() / 10.0));
        }
        json!({
            "t0_unix_ms": unix_ms(t0),
            "t0_after_slot_start_ms": unix_ms(t0) as i64 - (slot_start_unix * 1000) as i64,
            "ms_from_t0": rel,
        })
    }
}

struct InFlight {
    number: u64,
    hash: B256,
    cancel: CancellationToken,
}

pub struct Pipeline<P, E> {
    provider: P,
    evm_config: E,
    cfg: Arc<Config>,
    current: Option<InFlight>,
    /// When reth received each recent newPayload (`BlockReceived`).
    received: std::collections::VecDeque<(B256, SystemTime)>,
}

impl<P, E> Pipeline<P, E>
where
    P: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Clone + Send + Sync + 'static,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + Send + Sync + 'static,
{
    pub fn new(provider: P, evm_config: E, cfg: Config) -> Self {
        Self { provider, evm_config, cfg: Arc::new(cfg), current: None, received: Default::default() }
    }

    pub async fn run(mut self, mut events: impl futures::Stream<Item = ConsensusEngineEvent<EthPrimitives>> + Unpin) {
        while let Some(event) = events.next().await {
            match event {
                ConsensusEngineEvent::BlockReceived(num_hash) => {
                    self.received.push_back((num_hash.hash, SystemTime::now()));
                    if self.received.len() > 64 {
                        self.received.pop_front();
                    }
                }
                ConsensusEngineEvent::CanonicalBlockAdded(executed, _)
                | ConsensusEngineEvent::ForkBlockAdded(executed, _) => {
                    self.on_block(executed.recovered_block.clone());
                }
                ConsensusEngineEvent::CanonicalChainCommitted(head, _) => {
                    // The in-flight block left the canonical chain (a reorg
                    // to a sibling or back to an ancestor).
                    if let Some(cur) = &self.current {
                        if head.number() <= cur.number && head.hash() != cur.hash {
                            info!(number = cur.number, hash = %cur.hash, "in-flight block reorged out");
                            cur.cancel.cancel();
                        }
                    }
                }
                _ => {}
            }
        }
        warn!("engine event stream closed");
    }

    fn on_block(&mut self, block: Arc<RecoveredBlock<Block>>) {
        let (number, hash) = (block.number(), block.hash());
        if let Some(cur) = &self.current {
            if cur.hash == hash || number < cur.number {
                return; // already proving it, or an older side block
            }
            cur.cancel.cancel();
        }
        let timeline = Timeline::default();
        if let Some((_, t)) = self.received.iter().find(|(h, _)| *h == hash) {
            timeline.at("newpayload_received", *t);
        }
        timeline.mark("executed");
        let cancel = CancellationToken::new();
        self.current = Some(InFlight { number, hash, cancel: cancel.clone() });
        let (provider, evm_config, cfg) = (self.provider.clone(), self.evm_config.clone(), self.cfg.clone());
        tokio::spawn(async move {
            let dir = cfg.out_dir.join(format!("{number}-{}", &hex::encode(hash)[..16]));
            let t0 = Instant::now();
            let slot_start = block.header().timestamp;
            let result = run_job(&provider, &evm_config, &cfg, block, &dir, &cancel, &timeline).await;
            let timings = timeline.report(slot_start);
            let mut status = match &result {
                Ok(stage) => {
                    info!(number, %hash, stage, elapsed = ?t0.elapsed(), "job finished");
                    json!({ "number": number, "hash": hash, "result": stage })
                }
                Err(e) => {
                    error!(number, %hash, "job failed: {e:#}");
                    json!({ "number": number, "hash": hash, "result": "failed", "error": format!("{e:#}") })
                }
            };
            info!(number, timings = %timings, "job timings");
            status["timings"] = timings;
            if dir.exists() {
                let _ = std::fs::write(dir.join("status.json"), serde_json::to_vec_pretty(&status).unwrap());
            }
        });
    }
}

/// Run one block's job; returns the stage it ended at.
async fn run_job<P, E>(
    provider: &P,
    evm_config: &E,
    cfg: &Config,
    block: Arc<RecoveredBlock<Block>>,
    dir: &std::path::Path,
    cancel: &CancellationToken,
    timeline: &Timeline,
) -> Result<&'static str>
where
    P: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Clone + Send + Sync + 'static,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + Send + Sync + 'static,
{
    let (number, hash) = (block.number(), block.hash());
    let block_hash: Root = hash.0;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    // 1. Witness + ZEG0 input (blocking: state reads, re-execution, proofs).
    //    The parent's state is served once it is canonical (or persisted); a
    //    payload can arrive before the forkchoice update that makes its
    //    parent canonical (e.g. while catching up), so wait for it. A newer
    //    block cancels the wait.
    //    The witness also walks ancestor headers by hash, so wait for the
    //    parent's header too.
    let t = Instant::now();
    let parent = block.parent_hash();
    while provider.state_by_block_hash(parent).is_err() || !matches!(provider.header(parent), Ok(Some(_))) {
        if cancel.is_cancelled() {
            return Ok("cancelled");
        }
        if t.elapsed() > Duration::from_secs(36) {
            bail!("parent {parent} state/header never became available");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    timeline.mark("input_start");
    let t = Instant::now();
    let input = {
        let (provider, evm_config, block, chain_id) = (provider.clone(), evm_config.clone(), block.clone(), cfg.chain_id);
        tokio::task::spawn_blocking(move || crate::witness::build_input(&provider, &evm_config, chain_id, &block))
            .await??
    };
    let input_path = dir.join("input.bin");
    timeline.mark("input_done");
    std::fs::write(&input_path, &input)?;
    info!(number, bytes = input.len(), elapsed = ?t.elapsed(), "built input");
    if cancel.is_cancelled() {
        return Ok("cancelled");
    }

    // 2. Native pre-check: block hash and the expected public output.
    let t = Instant::now();
    let root = cfg.precheck.run(&input_path, &block_hash).await?;
    timeline.mark("precheck_done");
    info!(number, root = %hex::encode(root), elapsed = ?t.elapsed(), "pre-check passed");
    let public_input = PublicInput::new(root, cfg.chain_id);
    std::fs::write(
        dir.join("public_input.json"),
        serde_json::to_vec_pretty(&json!({
            "new_payload_request_root": format!("0x{}", hex::encode(public_input.new_payload_request_root)),
            "successful_validation": public_input.successful_validation,
            "chain_id": public_input.chain_id.to_string(),
            "schema_id": public_input.schema_id,
            "hash_tree_root": format!("0x{}", hex::encode(public_input.hash_tree_root())),
        }))?,
    )?;
    let Some(prover) = &cfg.prover else {
        return Ok("prechecked");
    };
    if cancel.is_cancelled() {
        return Ok("cancelled");
    }

    // 3. Prove (cancellable).
    let t = Instant::now();
    timeline.mark("prove_start");
    let proof = match prover.prove(&input, &root, cancel).await? {
        Outcome::Cancelled => {
            info!(number, %hash, "proof cancelled");
            return Ok("cancelled");
        }
        Outcome::Proved(p) => p,
    };
    timeline.mark("prove_done");
    if proof.root != root {
        bail!(
            "prover public output 0x{} != pre-check root 0x{}",
            hex::encode(proof.root),
            hex::encode(root)
        );
    }
    info!(number, elapsed = ?t.elapsed(), "public output matches");
    let Some(sub) = &cfg.submitter else {
        return Ok("emulated");
    };
    std::fs::write(dir.join("proof.bin"), &proof.data)?;

    // 4. Sign for the beacon block that commits to this payload. Not
    //    cancelled from here on: the proof stays valid for its block.
    let slot = block.header().slot_number.context("block has no slot_number (pre-Amsterdam)")?;
    let beacon_root = sub.beacon.wait_beacon_root(slot, &block_hash, Duration::from_secs(24)).await?;
    let fork_version = sub.params.fork_version_at_slot(slot);
    let message = ExecutionProofEnvelope { proof_data: proof.data, proof_type: sub.proof_type, beacon_block_root: beacon_root };
    let signed = sub.signer.sign(message, sub.validator_index, fork_version, &sub.params.genesis_validators_root);
    if !signer::verify(&signed, &sub.signer.pubkey(), fork_version, &sub.params.genesis_validators_root) {
        bail!("self-check of the proof signature failed");
    }
    std::fs::write(dir.join("signed.ssz"), crate::ssz::encode_signed_list(std::slice::from_ref(&signed)))?;
    info!(number, slot, beacon_root = %hex::encode(beacon_root), "signed proof");
    if !sub.submit {
        return Ok("signed");
    }

    // 5. Submit.
    sub.beacon.submit(std::slice::from_ref(&signed)).await?;
    info!(number, slot, "submitted proof");
    Ok("submitted")
}

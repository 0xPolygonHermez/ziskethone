//! One proof in flight: each payload, as soon as it is seen (the engine's
//! payload tap, or Lighthouse's gossip when `--zisk.lighthouse-early`),
//! starts a job (witness → pre-check → trim → prove → sign → submit). A newer
//! block — the next height, or a replacement at the same height — cancels the
//! previous job at any stage, including a proof already running on the
//! coordinator, which is `CancelJob`-ed to free the worker, and starts the new
//! one. A reorg or an invalid block also discards the in-flight proof.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use anyhow::{bail, Context, Result};
use futures::StreamExt;
use reth_engine_primitives::ConsensusEngineEvent;
use reth_ethereum::evm::primitives::ConfigureEvm;
use reth_ethereum::primitives::SealedBlock;
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
    pub submit: bool,
}

/// A payload seen by one of the job sources.
pub struct Incoming {
    pub block: SealedBlock<Block>,
    /// EIP-7928 block access list (RLP), Amsterdam payloads only.
    pub bal: Option<alloy_primitives::Bytes>,
    /// The beacon block committing to the payload, when the source knows it.
    pub beacon_root: Option<Root>,
    /// Timeline label of the source (`tap_payload`, `lh_envelope`).
    pub source: &'static str,
    pub at: SystemTime,
    /// Earlier timeline marks from the same source (e.g. `lh_gossip`).
    pub extra_marks: Vec<(&'static str, SystemTime)>,
}

pub struct Config {
    pub mode: Mode,
    pub chain_id: u64,
    pub out_dir: PathBuf,
    pub precheck: Precheck,
    pub prover: Option<Prover>,
    pub submitter: Option<Submitter>,
    /// After each BAL-built job, also build the re-execution input and
    /// compare (measurement aid; off the critical path).
    pub compare_exec: bool,
    /// Build a BAL input only once reth has executed the block: reth's
    /// parallel, BAL-driven prefetch has then loaded the trie pages our
    /// (sequential) proof walk reads; on a cold cache that walk is several
    /// times slower.
    pub after_execution: bool,
}

/// Wall-clock marks of one block's job, for the per-block timing report.
#[derive(Clone, Default)]
pub struct Timeline(Arc<std::sync::Mutex<Vec<(&'static str, SystemTime)>>>);

impl Timeline {
    pub fn has(&self, label: &str) -> bool {
        self.0.lock().unwrap().iter().any(|(l, _)| *l == label)
    }
    pub fn at(&self, label: &'static str, t: SystemTime) {
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
    /// Stop the job — including a proof already running on the coordinator,
    /// which is `CancelJob`-ed — when a newer block supersedes it.
    cancel: CancellationToken,
    /// The block left the canonical chain or is invalid: drop its proof.
    discard: CancellationToken,
}

pub struct Pipeline<P, E> {
    provider: P,
    evm_config: E,
    cfg: Arc<Config>,
    current: Option<InFlight>,
    /// Timelines of recent blocks by hash: sources and engine events mark
    /// them in whatever order they arrive.
    timelines: std::collections::VecDeque<(B256, Timeline)>,
    /// Blocks a job was started for (the first source wins).
    started: std::collections::VecDeque<B256>,
}

impl<P, E> Pipeline<P, E>
where
    P: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Clone + Send + Sync + 'static,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + Send + Sync + 'static,
{
    pub fn new(provider: P, evm_config: E, cfg: Config) -> Self {
        Self {
            provider,
            evm_config,
            cfg: Arc::new(cfg),
            current: None,
            timelines: Default::default(),
            started: Default::default(),
        }
    }

    fn timeline(&mut self, hash: B256) -> Timeline {
        if let Some((_, t)) = self.timelines.iter().find(|(h, _)| *h == hash) {
            return t.clone();
        }
        let t = Timeline::default();
        self.timelines.push_back((hash, t.clone()));
        if self.timelines.len() > 64 {
            self.timelines.pop_front();
        }
        t
    }

    pub async fn run(
        mut self,
        mut events: impl futures::Stream<Item = ConsensusEngineEvent<EthPrimitives>> + Unpin,
        mut payloads: tokio::sync::mpsc::Receiver<Incoming>,
    ) {
        loop {
            tokio::select! {
                Some(p) = payloads.recv() => self.on_payload(p),
                event = events.next() => {
                    let Some(event) = event else { break };
                    self.on_event(event);
                }
            }
        }
        warn!("engine event stream closed");
    }

    fn on_event(&mut self, event: ConsensusEngineEvent<EthPrimitives>) {
        match event {
            ConsensusEngineEvent::BlockReceived(num_hash) => {
                self.timeline(num_hash.hash).mark("newpayload_received");
            }
            ConsensusEngineEvent::CanonicalBlockAdded(executed, _) | ConsensusEngineEvent::ForkBlockAdded(executed, _) => {
                self.timeline(executed.recovered_block.hash()).mark("executed");
            }
            ConsensusEngineEvent::InvalidBlock { block, error } => {
                if let Some(cur) = self.current.as_ref().filter(|c| c.hash == block.hash()) {
                    warn!(number = cur.number, %error, "in-flight block is invalid");
                    cur.cancel.cancel();
                    cur.discard.cancel();
                }
            }
            ConsensusEngineEvent::CanonicalChainCommitted(head, _) => {
                // The in-flight block left the canonical chain (a reorg to a
                // sibling or back to an ancestor).
                if let Some(cur) = &self.current {
                    if head.number() <= cur.number && head.hash() != cur.hash {
                        info!(number = cur.number, hash = %cur.hash, "in-flight block reorged out");
                        cur.cancel.cancel();
                        cur.discard.cancel();
                    }
                }
            }
            _ => {}
        }
    }

    fn on_payload(&mut self, p: Incoming) {
        let (number, hash) = (p.block.number, p.block.hash());
        let timeline = self.timeline(hash);
        for (label, at) in &p.extra_marks {
            timeline.at(label, *at);
        }
        timeline.at(p.source, p.at);
        if self.started.contains(&hash) {
            return; // another source was first
        }
        if let Some(cur) = &self.current {
            if number < cur.number {
                return; // an older side block
            }
            cur.cancel.cancel();
        }
        self.started.push_back(hash);
        if self.started.len() > 64 {
            self.started.pop_front();
        }
        let (cancel, discard) = (CancellationToken::new(), CancellationToken::new());
        self.current = Some(InFlight { number, hash, cancel: cancel.clone(), discard: discard.clone() });
        let (provider, evm_config, cfg) = (self.provider.clone(), self.evm_config.clone(), self.cfg.clone());
        tokio::spawn(async move {
            let dir = cfg.out_dir.join(format!("{number}-{}", &hex::encode(hash)[..16]));
            let t0 = Instant::now();
            let slot_start = p.block.timestamp;
            let source = p.source;
            let block = p.block.clone();
            let has_bal = p.bal.is_some();
            let result = run_job(&provider, &evm_config, &cfg, p, &dir, &cancel, &discard, &timeline).await;
            if cfg.compare_exec && has_bal && result.is_ok() && !cancel.is_cancelled() {
                if let Err(e) = compare_exec(&provider, &evm_config, &cfg, &block, &dir).await {
                    warn!(number, "compare-exec: {e:#}");
                }
            }
            let timings = timeline.report(slot_start);
            let mut status = match &result {
                Ok(stage) => {
                    info!(number, %hash, stage, elapsed = ?t0.elapsed(), "job finished");
                    json!({ "number": number, "hash": hash, "result": stage, "source": source })
                }
                Err(e) => {
                    error!(number, %hash, "job failed: {e:#}");
                    json!({ "number": number, "hash": hash, "result": "failed", "error": format!("{e:#}"), "source": source })
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

/// Build the input on a blocking thread: from the BAL when the payload has
/// one, else by re-executing. Returns the sources and whether they came
/// from the BAL (a superset to trim).
async fn build_sources<P, E>(
    provider: &P,
    evm_config: &E,
    chain_id: u64,
    block: &SealedBlock<Block>,
    bal: Option<&alloy_primitives::Bytes>,
) -> Result<(rust_input_gen::offline::OfflineSources, bool)>
where
    P: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Clone + Send + Sync + 'static,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + Send + Sync + 'static,
{
    let (provider, evm_config, block, bal) = (provider.clone(), evm_config.clone(), block.clone(), bal.cloned());
    tokio::task::spawn_blocking(move || match bal {
        Some(bal) => Ok((crate::witness::sources_from_bal(&provider, &evm_config, chain_id, &block, &bal)?, true)),
        None => {
            let block = block.try_recover().map_err(|e| anyhow::anyhow!("recovering senders: {e}"))?;
            Ok((crate::witness::sources_by_execution(&provider, &evm_config, chain_id, &block)?, false))
        }
    })
    .await?
}

/// Run one block's job; returns the stage it ended at.
async fn run_job<P, E>(
    provider: &P,
    evm_config: &E,
    cfg: &Config,
    p: Incoming,
    dir: &std::path::Path,
    cancel: &CancellationToken,
    discard: &CancellationToken,
    timeline: &Timeline,
) -> Result<&'static str>
where
    P: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Clone + Send + Sync + 'static,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + Send + Sync + 'static,
{
    let block = &p.block;
    let (number, hash) = (block.number, block.hash());
    let block_hash: Root = hash.0;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    // 1. The parent's state is served once it is canonical (or persisted);
    //    a payload can arrive before the forkchoice update that makes its
    //    parent canonical (e.g. while catching up), so wait for it. The
    //    witness also walks ancestor headers by hash, so wait for the
    //    parent's header too. A newer block cancels the wait.
    let t = Instant::now();
    let parent = block.parent_hash;
    while provider.state_by_block_hash(parent).is_err() || !matches!(provider.header(parent), Ok(Some(_))) {
        if cancel.is_cancelled() {
            return Ok("cancelled");
        }
        if t.elapsed() > Duration::from_secs(36) {
            bail!("parent {parent} state/header never became available");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    if cfg.after_execution && p.bal.is_some() {
        let t = Instant::now();
        while !timeline.has("executed") {
            if cancel.is_cancelled() {
                return Ok("cancelled");
            }
            if t.elapsed() > Duration::from_secs(12) {
                bail!("reth did not execute the block within 12 s");
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    // 2. Witness + ZEG0 input: from the BAL when present (its transactions
    //    run in parallel only to find the BLOCKHASH ancestors), else by
    //    re-executing.
    timeline.mark("input_start");
    let t = Instant::now();
    let (sources, from_bal) = build_sources(provider, evm_config, cfg.chain_id, block, p.bal.as_ref()).await?;
    timeline.mark("witness_done");
    let input = rust_input_gen::offline::encode_binary(&sources)?;
    timeline.mark("input_done");
    let input_path = dir.join("input.bin");
    std::fs::write(&input_path, &input)?;
    info!(number, bytes = input.len(), from_bal, elapsed = ?t.elapsed(), "built input");
    let Some(prover) = &cfg.prover else {
        return Ok("built");
    };
    if cancel.is_cancelled() {
        return Ok("cancelled");
    }

    // 3. Prove. Cancellable right through to completion: a newer block
    //    `CancelJob`-s a proof already running on the coordinator.
    timeline.mark("prove_start");
    let proof = match prover.prove(&input, cancel).await? {
        Outcome::Cancelled => {
            info!(number, %hash, "proof cancelled");
            return Ok("cancelled");
        }
        Outcome::Proved(p) => p,
    };
    timeline.mark("prove_done");
    if discard.is_cancelled() {
        info!(number, %hash, "proof discarded: the block left the canonical chain or is invalid");
        return Ok("discarded");
    }
    if let Some(root) = proof.root {
        info!(number, root = %hex::encode(root), "public output");
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
    }
    let Some(sub) = &cfg.submitter else {
        return Ok("emulated");
    };
    std::fs::write(dir.join("proof.bin"), &proof.data)?;

    // 6. Sign for the beacon block that commits to this payload. Not
    //    cancelled from here on: the proof stays valid for its block.
    let slot = block.header().slot_number.context("block has no slot_number (pre-Amsterdam)")?;
    let beacon_root = match p.beacon_root {
        Some(r) => r,
        None => sub.beacon.wait_beacon_root(slot, &block_hash, Duration::from_secs(24)).await?,
    };
    let fork_version = sub.params.fork_version_at_slot(slot);
    let message = ExecutionProofEnvelope { proof_data: proof.data, proof_type: crate::ssz::ZISK_PROOF_TYPE, beacon_block_root: beacon_root };
    let signed = sub.signer.sign(message, sub.validator_index, fork_version, &sub.params.genesis_validators_root);
    if !signer::verify(&signed, &sub.signer.pubkey(), fork_version, &sub.params.genesis_validators_root) {
        bail!("self-check of the proof signature failed");
    }
    std::fs::write(dir.join("signed.ssz"), crate::ssz::encode_signed_list(std::slice::from_ref(&signed)))?;
    info!(number, slot, beacon_root = %hex::encode(beacon_root), "signed proof");
    if !sub.submit {
        return Ok("signed");
    }

    // 7. Submit.
    sub.beacon.submit(std::slice::from_ref(&signed)).await?;
    info!(number, slot, "submitted proof");
    Ok("submitted")
}


/// Build the re-execution input of `block` next to the BAL-built one
/// (`input.exec.bin`) and check both give the same root.
async fn compare_exec<P, E>(provider: &P, evm_config: &E, cfg: &Config, block: &SealedBlock<Block>, dir: &std::path::Path) -> Result<()>
where
    P: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Clone + Send + Sync + 'static,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + Send + Sync + 'static,
{
    let t = Instant::now();
    let (sources, _) = build_sources(provider, evm_config, cfg.chain_id, block, None).await?;
    let elapsed = t.elapsed();
    let path = dir.join("input.exec.bin");
    let bytes = rust_input_gen::offline::encode_binary(&sources)?;
    std::fs::write(&path, &bytes)?;
    let exec = cfg.precheck.run(&path, &block.hash().0).await?;
    let bal = cfg.precheck.run(&dir.join("input.bin"), &block.hash().0).await?;
    let bal_len = std::fs::metadata(dir.join("input.bin"))?.len();
    info!(
        number = block.number,
        same_root = exec.root == bal.root,
        root = %hex::encode(bal.root),
        exec_bytes = bytes.len(),
        bal_bytes = bal_len,
        exec_build = ?elapsed,
        guest_blockhash = ?bal.used_blocks,
        guest_codes = bal.used_codes.len(),
        "compare-exec"
    );
    if exec.root != bal.root {
        bail!("roots differ: exec 0x{} bal 0x{}", hex::encode(exec.root), hex::encode(bal.root));
    }
    Ok(())
}

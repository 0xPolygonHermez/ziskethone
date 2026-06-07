//! Frozen, in-memory representation of every input the binary-format
//! encoder needs.
//!
//! The live-RPC path (`fetch_offline_sources_online`) does all its
//! network work up front, populates `OfflineSources`, then hands off
//! to `build_binary(&sources, &out_path)` — a pure function that
//! never touches the network. The same frozen bundle can be
//! serialized to JSON, transmitted, and replayed elsewhere — that's
//! what the second binary (`input-gen-from-manifest`) and the
//! EEST→reth→cpp-guest test pipeline consume.
//!
//! Keeping the encoder pure also lets us byte-equivalence-test the
//! offline path against the online one (see `tests/roundtrip.rs`):
//! same OfflineSources → same bytes, with or without a JSON
//! round-trip in between.

use std::collections::BTreeSet;
use std::path::Path;

use alloy::primitives::{Address, B256};
use alloy::rpc::types::Block;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::enrich;
use crate::rpc::{ExecutionWitness, Prestate, PrestateDiff};
use crate::sections;
use crate::state_root;
use crate::touchset::TouchSet;
use crate::verify;
use crate::writer::Writer;

/// All inputs the binary encoder needs, fully resolved (no RPC
/// callbacks remain). Either populated by the live-RPC path or
/// loaded from a manifest JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineSources {
    /// The block being executed. Full transaction envelopes.
    pub current: Block,
    /// The parent block (header only — we need `parent.state_root`
    /// as the trie-walk anchor and re-derive the parent's block hash
    /// from its canonical header RLP).
    pub parent: Block,
    /// Ancestor chain: `ancestors[0]` is the parent, `ancestors[i]`
    /// is the (i+1)-th ancestor. The cpp-guest's BLOCKHASH walks
    /// this list; EIP-2935 system-call ring-buffer is separate.
    pub ancestors: Vec<Block>,
    /// Block-start state for every account the EVM accesses (or that
    /// post-tx-injection adds: system contracts, withdrawal
    /// recipients). Values come from the `prestateTracer` non-diff
    /// run, then are enriched + injected.
    pub prestate: Prestate,
    /// Per-block field-level diff from `prestateTracer --diffMode`.
    /// Drives the `is_read_only` flag on Accounts/Storages.
    pub diff: PrestateDiff,
    /// Trie nodes + bytecodes + preimages from
    /// `debug_executionWitness`. The state-root walker consumes
    /// `state` directly.
    pub witness: ExecutionWitness,
    /// (addr, slot) pairs that the pre/post-block system calls
    /// write — must be marked writable in the Storages section so
    /// the cpp-guest doesn't reject them as read-only.
    pub system_contract_slots: BTreeSet<(Address, B256)>,
    /// True when this block runs under the Osaka (Fusaka) fork. Osaka
    /// is timestamp-activated and adds no header field over Prague, so
    /// it can't be inferred from the block structure — the live-RPC path
    /// resolves it from the node's `eth_config`. Surfaced to the guest
    /// via the ConsensusInfo `fork_id` so it dispatches at `EVMC_OSAKA`
    /// (enabling EIP-7939 CLZ, the P256VERIFY precompile, …). Defaults
    /// to false for manifests that pre-date the field.
    #[serde(default)]
    pub is_osaka: bool,
    /// BLOB_BASE_FEE_UPDATE_FRACTION for this block's blob schedule (EIP-4844/
    /// 7691/7892). Carried per-block because mainnet-Osaka and EEST-Osaka share
    /// `fork_id` yet use different schedules, and mainnet evolves it at each BPO
    /// fork. Surfaced to the guest via ConsensusInfo. `serde(default)` (0) keeps
    /// older manifests decoding to the guest's current-mainnet fallback.
    #[serde(default)]
    pub blob_base_fee_update_fraction: u64,
}

/// Encode an `OfflineSources` bundle to the cpp-guest's binary
/// format and write it to `output`. Pure: no network, no env access.
/// Both the live-RPC `input-gen` binary and the manifest-driven
/// `input-gen-from-manifest` binary funnel through here, so the two
/// paths are guaranteed to produce byte-identical outputs from the
/// same `OfflineSources`.
pub fn build_binary(sources: &OfflineSources, output: &Path) -> Result<()> {
    // Enrich prestate from the witness storage-trie leaves before
    // building the TouchSet. The online RPC path used to do this in
    // main.rs; offline manifests (notably from eest-witness-gen)
    // arrive with a prestate populated only from reth's BundleState,
    // which omits slots the EVM READ but didn't WRITE. The witness
    // has those leaves, and we pull them in here so the cpp-guest's
    // Storages table covers every (addr, slot) the EVM touches.
    let mut prestate = sources.prestate.clone();
    enrich::enrich_storage_slots_from_witness(
        sources.parent.header.state_root,
        &sources.witness,
        &mut prestate,
    )?;
    // Inject every address that appears in the tx envelope: sender,
    // tx.to, EIP-2930 access list, and EIP-7702 authorization signers
    // (recovered from the auth signatures). cpp-guest registers the
    // authority addresses in its Accounts table even when the auth is
    // invalid (test_account_warming, etc.), and fatals if a referenced
    // address isn't in the table. The eest-witness-gen bridge can't
    // pre-recover authorities (it would require ECDSA), so we do it
    // here from the manifest's tx envelopes.
    enrich::inject_tx_addresses(&mut prestate, &sources.current);

    let touch = TouchSet::build(&prestate, &sources.diff);
    info!(
        accounts = touch.addrs.len(),
        slots = touch.slots.len(),
        "built TouchSet",
    );

    verify::check(
        sources.parent.header.state_root,
        &sources.witness,
        &prestate,
        &sources.diff,
        &touch,
    )?;

    let mut w = Writer::new();
    sections::write_magic(&mut w);
    sections::write_consensus_info(
        &mut w,
        &sources.current,
        &sources.parent,
        sources.is_osaka,
        sources.blob_base_fee_update_fraction,
    );
    sections::write_transactions(&mut w, &sources.current)?;
    sections::write_contracts(&mut w, &prestate, &sources.diff, &sources.current)?;
    sections::write_previous_blocks(&mut w, &sources.ancestors);
    // The StateRoot trie hints are now witness-only: `state_root::write`
    // transcribes the pre-state MPT straight from `witness.state` +
    // `witness.keys`, emitting every revealed leaf and leaving created keys
    // for the guest to insert. It no longer consumes prestate/diff/touch.
    state_root::write(
        &mut w,
        sources.parent.header.state_root,
        &sources.witness.state,
        &sources.witness.keys,
    )?;

    let bytes = w.into_bytes();
    if let Some(parent_dir) = output.parent() {
        std::fs::create_dir_all(parent_dir)
            .with_context(|| format!("creating output dir {}", parent_dir.display()))?;
    }
    std::fs::write(output, &bytes)
        .with_context(|| format!("writing {}", output.display()))?;

    info!(path = %output.display(), bytes = bytes.len(), "wrote input file");
    Ok(())
}

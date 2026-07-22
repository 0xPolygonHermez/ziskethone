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
    /// TARGET_BLOB_GAS_PER_BLOCK (target blob count × GAS_PER_BLOB) for this
    /// block's blob schedule (EIP-4844/7691/7892) — sibling of
    /// `blob_base_fee_update_fraction` above, carried per-block for the same
    /// reason. The guest uses it to independently re-derive `excess_blob_gas`
    /// from the parent block and reject a header whose claimed value doesn't
    /// match. `serde(default)` (0) keeps older manifests decoding; those
    /// blocks just skip the check (guest gates it on the field being
    /// meaningful, i.e. Cancun-or-later — see `zisk_state_db.cpp`).
    #[serde(default)]
    pub target_blob_gas_per_block: u64,
    /// MAX_BLOB_GAS_PER_BLOCK (max blob count × GAS_PER_BLOB) — sibling of
    /// `target_blob_gas_per_block` above, same reason. The guest needs both
    /// for the EIP-7918 (Osaka+) reserve-price branch of the
    /// `excess_blob_gas` formula.
    #[serde(default)]
    pub max_blob_gas_per_block: u64,
}

/// Encode an `OfflineSources` bundle to the cpp-guest's binary
/// format and write it to `output`. Pure: no network, no env access.
/// Both the live-RPC `input-gen` binary and the manifest-driven
/// `input-gen-from-manifest` binary funnel through here, so the two
/// paths are guaranteed to produce byte-identical outputs from the
/// same `OfflineSources`.
pub fn build_binary(sources: &OfflineSources, output: &Path) -> Result<()> {
    let bytes = encode_binary(sources)?;
    if let Some(parent_dir) = output.parent() {
        std::fs::create_dir_all(parent_dir)
            .with_context(|| format!("creating output dir {}", parent_dir.display()))?;
    }
    std::fs::write(output, &bytes).with_context(|| format!("writing {}", output.display()))?;
    info!(path = %output.display(), bytes = bytes.len(), "wrote input file");
    Ok(())
}

/// Encode an `OfflineSources` bundle into the in-memory `ZEG0` container,
/// returning the bytes without touching the filesystem. `build_binary` is a
/// thin wrapper that writes the result to disk; in-process consumers (the
/// `live` module's `fetch_and_build_*` entry points) use this directly to
/// avoid a tempfile round-trip.
pub fn encode_binary(sources: &OfflineSources) -> Result<Vec<u8>> {
    // `prestate`/`diff` are populated only by the manifest path (eest-witness-gen
    // ships a BundleState prestate). The online RPC path is witness-only and
    // leaves them empty, so the enrich + TouchSet + verify below are pure
    // no-ops there — skip them. The output bytes come from `witness` +
    // `prestate` (codes) regardless; `state_root::write` no longer consumes
    // prestate/diff/touch at all (see below).
    let mut prestate = sources.prestate.clone();
    if !prestate.is_empty() {
        // Enrich prestate from the witness storage-trie leaves (the manifest
        // prestate omits slots the EVM READ but didn't WRITE), then inject the
        // tx-envelope addresses (sender/to/access-list/EIP-7702 authorities)
        // the guest must have in its Accounts table. Both only matter when a
        // manifest prestate is present.
        enrich::enrich_storage_slots_from_witness(
            sources.parent.header.state_root,
            &sources.witness,
            &mut prestate,
        )?;
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
    }

    let mut w = Writer::new();
    sections::write_magic(&mut w);
    sections::write_consensus_info(
        &mut w,
        &sources.current,
        &sources.parent,
        sources.is_osaka,
        sources.blob_base_fee_update_fraction,
        sources.target_blob_gas_per_block,
        sources.max_blob_gas_per_block,
    );
    sections::write_transactions(&mut w, &sources.current)?;
    sections::write_contracts(&mut w, &prestate, &sources.witness, &sources.current)?;
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

    Ok(w.into_bytes())
}

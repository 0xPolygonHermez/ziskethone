//! Wire-format mirror of `rust_input_gen::offline::OfflineSources`.
//!
//! `eest-witness-gen` lives in a different alloy major-version
//! universe than `rust-input-gen` (alloy 1.5/2.0 split-crates vs.
//! alloy 0.8 umbrella) — see `Cargo.toml` for the deeper reason —
//! so the two can't share Rust types. Instead they share a **JSON
//! shape**: this struct serializes via serde to the exact
//! payload that `input-gen-from-manifest` deserializes back into
//! `OfflineSources`. End-to-end shape compat is enforced by the
//! round-trip on a real fixture.
//!
//! When changing this file: keep field names, field order, and
//! `#[serde(...)]` attributes in lock-step with
//! `rust-input-gen/src/{offline.rs, rpc.rs}`.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};

/// Mirror of `rust_input_gen::offline::OfflineSources`.
///
/// The Block-typed fields (`current`, `parent`, `ancestors`) are
/// stored as raw `serde_json::Value` rather than a typed
/// `alloy_rpc_types_eth::Block`. Reason: alloy 0.8 (rust-input-gen)
/// and alloy 2.x (this crate) differ on some `Transaction` generic
/// parameters but agree on the JSON-RPC wire format. Holding the
/// payload as `Value` here means we hand-build the eth_getBlockByNumber
/// shape exactly, with no type-mismatch surface between the two
/// alloy universes. The bridge in `bridge.rs` materializes these
/// Values from reth's typed output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSources {
    pub current: serde_json::Value,
    pub parent: serde_json::Value,
    pub ancestors: Vec<serde_json::Value>,
    pub prestate: Prestate,
    pub diff: PrestateDiff,
    pub witness: ExecutionWitness,
    pub system_contract_slots: BTreeSet<(Address, B256)>,
    /// True when this block runs under Osaka (Fusaka). Osaka is
    /// timestamp-activated and adds no header field over Prague, so it
    /// can't be inferred from the block structure — the bridge resolves
    /// it from the fixture's chain spec and surfaces it to the guest
    /// (via `OfflineSources.is_osaka` → ConsensusInfo `fork_id`) so the
    /// guest dispatches at `EVMC_OSAKA` (EIP-7939 CLZ, MODEXP gas, the
    /// P256VERIFY precompile, …). `serde(default)` keeps older manifests
    /// (which omit the field) decoding as Prague.
    #[serde(default)]
    pub is_osaka: bool,
    /// BLOB_BASE_FEE_UPDATE_FRACTION for this block's blob schedule. Resolved
    /// from the fixture's chain spec (its `config.blobSchedule`) so blob base
    /// fees match the fork — EEST base-Osaka (5,007,716) differs from the
    /// guest's mainnet default. Deserializes into `OfflineSources` of the same
    /// name; `serde(default)` (0) keeps older manifests on the guest fallback.
    #[serde(default)]
    pub blob_base_fee_update_fraction: u64,
    /// TARGET_BLOB_GAS_PER_BLOCK (target blob count × GAS_PER_BLOB) for this
    /// block's blob schedule. Resolved from the fixture's chain spec, same
    /// source as `blob_base_fee_update_fraction` above — the guest uses it
    /// to independently re-derive `excess_blob_gas` from the parent block
    /// and reject a header whose claimed value doesn't match. Deserializes
    /// into `OfflineSources` of the same name; `serde(default)` (0) keeps
    /// older manifests decoding (those blocks just skip the check).
    #[serde(default)]
    pub target_blob_gas_per_block: u64,
    /// MAX_BLOB_GAS_PER_BLOCK — sibling of `target_blob_gas_per_block`
    /// above, same source and reason. The guest needs both for the
    /// EIP-7918 (Osaka+) reserve-price branch of the `excess_blob_gas`
    /// formula.
    #[serde(default)]
    pub max_blob_gas_per_block: u64,
}

/// Mirror of `rust_input_gen::rpc::Prestate`.
pub type Prestate = BTreeMap<Address, AccountPrestate>;

/// Mirror of `rust_input_gen::rpc::AccountPrestate`. The `skip_*`
/// attrs must match exactly — input-gen-from-manifest decodes
/// missing fields as `None` / empty, but extra `null` values
/// elsewhere would be silently equivalent on the read side, so the
/// shape only matters for human-readable parity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountPrestate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Bytes>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub storage: BTreeMap<B256, B256>,
}

/// Mirror of `rust_input_gen::rpc::PrestateDiff`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrestateDiff {
    pub pre: Prestate,
    pub post: Prestate,
}

/// Mirror of `rust_input_gen::rpc::ExecutionWitness`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionWitness {
    pub state: Vec<Bytes>,
    pub codes: Vec<Bytes>,
    pub keys: Vec<Bytes>,
}

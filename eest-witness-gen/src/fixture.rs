//! Minimal EEST blockchain-test fixture model.
//!
//! Mirrors the shape of `testing/ef-tests/src/models.rs` in reth
//! (v2.2.0) — we don't depend on reth here because the parser only
//! needs serde + alloy primitives, and pulling all of reth's
//! transitive graph just to read JSON would balloon build time
//! by ~150 crates.
//!
//! When we wire in reth's executor in the next phase, we'll either
//! switch to importing reth's `BlockchainTest` model (which has
//! extra fields we don't need today) OR keep this minimal model and
//! convert into reth's `SealedBlock` / `GenesisAccount` types at the
//! executor boundary. Either is fine; the field names and JSON
//! shape match.

use std::collections::BTreeMap;

use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use serde::Deserialize;

/// Top-level shape of an EEST blockchain-test JSON file:
/// `{ "<test_name>": BlockchainTest, ... }`. The key is the test
/// label (includes fork suffix like `[fork=Prague]`).
pub type Fixture = BTreeMap<String, BlockchainTest>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockchainTest {
    /// Genesis block header (synthetic, defines pre-chain state).
    pub genesis_block_header: Header,
    /// Sequence of blocks to apply on top of genesis.
    pub blocks: Vec<Block>,
    /// Pre-state, keyed by address. Loaded into the genesis state.
    pub pre: BTreeMap<Address, Account>,
    /// Optional post-state for cross-check.
    #[serde(default)]
    pub post_state: Option<BTreeMap<Address, Account>>,
    /// Hash of the last canonical block — the test's success
    /// condition (cpp-guest's computed block hash must match).
    pub lastblockhash: B256,
    /// Fork specification (e.g. `Prague`, `Osaka`, `Cancun`).
    pub network: String,
    #[serde(default, rename = "genesisRLP")]
    pub genesis_rlp: Option<Bytes>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    /// Decoded header. Present on canonical blocks; missing on
    /// blocks that test specifically expect to fail decoding.
    #[serde(default)]
    pub block_header: Option<Header>,
    /// RLP of the full block (header + txs + withdrawals + ...).
    /// This is the canonical input the executor consumes.
    pub rlp: Bytes,
    /// If the test expects this block to fail, the exception
    /// message. We surface these so the runner can classify
    /// expected-failure tests separately.
    #[serde(default)]
    pub expect_exception: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub bloom: Bloom,
    pub coinbase: Address,
    pub difficulty: U256,
    pub extra_data: Bytes,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub hash: B256,
    pub mix_hash: B256,
    pub nonce: B64,
    pub number: U256,
    pub parent_hash: B256,
    pub receipt_trie: B256,
    pub state_root: B256,
    pub timestamp: U256,
    pub transactions_trie: B256,
    pub uncle_hash: B256,
    #[serde(default)]
    pub base_fee_per_gas: Option<U256>,
    #[serde(default)]
    pub withdrawals_root: Option<B256>,
    #[serde(default)]
    pub blob_gas_used: Option<U256>,
    #[serde(default)]
    pub excess_blob_gas: Option<U256>,
    #[serde(default)]
    pub parent_beacon_block_root: Option<B256>,
    #[serde(default)]
    pub requests_hash: Option<B256>,
}

#[derive(Debug, Deserialize)]
pub struct Account {
    pub balance: U256,
    pub nonce: U256,
    pub code: Bytes,
    #[serde(default)]
    pub storage: BTreeMap<U256, U256>,
}

/// Parse a single EEST blockchain-test JSON file. The file contains
/// one or more named tests; we return them all keyed by test label.
pub fn load_fixture(path: &std::path::Path) -> anyhow::Result<Fixture> {
    use anyhow::Context as _;
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing EEST fixture {}", path.display()))
}

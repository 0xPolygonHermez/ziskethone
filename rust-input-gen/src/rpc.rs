//! Ethereum RPC client wrapper.
//!
//! Fetches everything the guest needs to statelessly re-execute a block:
//! the target block + parent header, transactions, withdrawals, recent
//! ancestor headers (for `BLOCKHASH` opcode), and the execution witness
//! (state / storage trie nodes + contract bytecodes) returned by
//! `debug_executionWitness`.
//!
//! NOTE: `debug_executionWitness` is only available on debug-enabled nodes
//! (Geth/Reth with `--http.api debug`). The exact response shape is still
//! evolving across client versions; the parsing here treats unknown fields
//! leniently.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};

/// Number of ancestor headers to fetch (covers the `BLOCKHASH` opcode window).
pub const ANCESTOR_DEPTH: u64 = 256;

pub struct RpcClient {
    url: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Debug)]
pub struct BlockBundle {
    pub chain_id: u64,
    pub block_number: u64,
    pub parent_header_rlp: Vec<u8>,
    pub current_header_rlp: Vec<u8>,
    pub transactions_rlp: Vec<Vec<u8>>,
    pub withdrawals_rlp: Vec<Vec<u8>>,
    pub ancestor_headers_rlp: Vec<Vec<u8>>,
    pub state_trie_nodes: Vec<Vec<u8>>,
    pub storage_trie_nodes: Vec<Vec<u8>>,
    pub bytecodes: Vec<Vec<u8>>,
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), http: reqwest::Client::new() }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp: JsonRpcResponse = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("RPC request {method} failed"))?
            .json()
            .await
            .with_context(|| format!("Decoding RPC response for {method}"))?;
        if let Some(err) = resp.error {
            return Err(anyhow!("RPC {method} returned error: {err}"));
        }
        resp.result.ok_or_else(|| anyhow!("RPC {method} returned no result"))
    }

    pub async fn chain_id(&self) -> Result<u64> {
        let v = self.call("eth_chainId", json!([])).await?;
        parse_hex_u64(&v)
    }

    /// Fetch the full `BlockBundle` for `block_number`. This is the high-level
    /// entry point used by `main.rs`.
    pub async fn fetch_block_bundle(&self, block_number: u64) -> Result<BlockBundle> {
        // TODO: implement using:
        //   - `eth_getBlockByNumber` (for header + tx list, with `true` to include txs)
        //   - `debug_getRawHeader`   (for canonical RLP of headers)
        //   - `debug_getRawTransaction` per tx
        //   - `debug_executionWitness` (state + storage nodes + bytecodes)
        //   - loop `eth_getBlockByNumber` for ANCESTOR_DEPTH parents
        //
        // For the initial scaffold we return an empty bundle so the binary
        // writer can be exercised end-to-end without network access.
        let chain_id = self.chain_id().await?;
        tracing::info!(chain_id, "fetched chain_id from RPC");
        Ok(BlockBundle {
            chain_id,
            block_number,
            parent_header_rlp: Vec::new(),
            current_header_rlp: Vec::new(),
            transactions_rlp: Vec::new(),
            withdrawals_rlp: Vec::new(),
            ancestor_headers_rlp: Vec::new(),
            state_trie_nodes: Vec::new(),
            storage_trie_nodes: Vec::new(),
            bytecodes: Vec::new(),
        })
    }
}

fn parse_hex_u64(v: &Value) -> Result<u64> {
    let s = v.as_str().ok_or_else(|| anyhow!("expected hex string, got {v}"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).with_context(|| format!("parsing hex u64 {s}"))
}

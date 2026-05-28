//! Thin alloy-based JSON-RPC client wrapper.
//!
//! Each method maps directly to the standard JSON-RPC name. The
//! returned types are alloy's typed structs (Block / Header /
//! EIP1186AccountProofResponse) so encoders can read fields directly.
//! The prestate-tracer responses are parsed via `serde_json::Value`
//! since the wire shape differs slightly between clients.

use std::collections::{BTreeMap, HashSet};

use alloy::eips::BlockId;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::{
    Block, BlockNumberOrTag, BlockTransactionsKind, EIP1186AccountProofResponse,
};
use alloy::transports::http::{Client as HttpClient, Http};
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tracing::warn;

pub struct Client {
    provider: RootProvider<Http<HttpClient>>,
}

/// Block-start values for one account, as reported by the
/// `prestateTracer`. Fields are optional because the tracer omits
/// fields that the tx didn't touch.
#[derive(Debug, Clone, Default)]
pub struct AccountPrestate {
    pub balance: Option<U256>,
    pub nonce:   Option<u64>,
    pub code:    Option<Bytes>,
    pub storage: BTreeMap<B256, B256>,
}

pub type Prestate = BTreeMap<Address, AccountPrestate>;

/// Aggregated diff-mode result. `pre` and `post` cover only fields
/// that changed during the block.
#[derive(Debug, Clone, Default)]
pub struct PrestateDiff {
    pub pre:  Prestate,
    pub post: Prestate,
}

/// Stateless-execution witness for one block, as returned by
/// `debug_executionWitness`. The cpp-guest consumes `state` directly
/// (via the StateRoot trie-hint stream); `keys` provides the
/// keccak-preimage map needed to attribute divergent-sibling MPT
/// leaves to their addresses/slots; `codes` is currently unused (we
/// already have bytecodes via the prestate tracer) but kept so future
/// callers don't need a second RPC.
#[derive(Debug, Clone, Default)]
pub struct ExecutionWitness {
    pub state: Vec<Bytes>,
    pub codes: Vec<Bytes>,
    pub keys:  Vec<Bytes>,
}

impl Client {
    /// Build an HTTP provider against `url`.
    pub fn new(url: &str) -> Result<Self> {
        let parsed = url
            .parse()
            .with_context(|| format!("invalid RPC URL {url}"))?;
        let provider = ProviderBuilder::new().on_http(parsed);
        Ok(Self { provider })
    }

    /// `eth_getBlockByNumber(n, false)` — header + tx hash list. Fast;
    /// used for the parent and earlier ancestors where we only need
    /// the header fields.
    pub async fn block(&self, number: u64) -> Result<Block> {
        self.provider
            .get_block_by_number(
                BlockNumberOrTag::Number(number),
                BlockTransactionsKind::Hashes,
            )
            .await
            .with_context(|| format!("eth_getBlockByNumber({number})"))?
            .ok_or_else(|| anyhow!("block {number} not found"))
    }

    /// `eth_getBlockByNumber(n, true)` — header + full canonical
    /// transaction envelopes. Used for the current block so the
    /// `Transactions` encoder can re-emit the wire envelopes and
    /// recover sender pubkeys.
    pub async fn block_full(&self, number: u64) -> Result<Block> {
        self.provider
            .get_block_by_number(
                BlockNumberOrTag::Number(number),
                BlockTransactionsKind::Full,
            )
            .await
            .with_context(|| format!("eth_getBlockByNumber({number}, full)"))?
            .ok_or_else(|| anyhow!("block {number} not found"))
    }

    /// `debug_traceBlockByNumber(block, prestateTracer)` — non-diff
    /// mode. Returns the union of every (account → balance/nonce/code/
    /// storage) the block's txs touched, with **block-start** values
    /// (i.e. the first observed value per (addr, slot) wins across
    /// the per-tx traces).
    pub async fn prestate(&self, block: u64) -> Result<Prestate> {
        let raw = self.debug_trace_prestate(block, false).await?;
        Ok(merge_prestate_traces(&raw, /*first_wins=*/ true))
    }

    /// `debug_traceBlockByNumber(block, prestateTracer, diffMode=true)`.
    /// Returns aggregated `pre` and `post` maps covering only the
    /// fields that changed during the block.
    pub async fn prestate_diff(&self, block: u64) -> Result<PrestateDiff> {
        let raw = self.debug_trace_prestate(block, true).await?;
        let traces = raw
            .as_array()
            .ok_or_else(|| anyhow!("debug_traceBlockByNumber: expected array"))?;
        let mut diff = PrestateDiff::default();
        for tx in traces {
            let inner = tx.get("result").unwrap_or(tx);
            if let Some(pre) = inner.get("pre") {
                merge_one_into(&mut diff.pre, pre, /*first_wins=*/ true, None);
            }
            if let Some(post) = inner.get("post") {
                // For the `post` side, last-wins captures the final
                // value seen in the block.
                merge_one_into(&mut diff.post, post, /*first_wins=*/ false, None);
            }
        }
        Ok(diff)
    }

    /// `eth_getProof(addr, slots)` at `block`. Returns the canonical
    /// block-end balance/nonce/code_hash/storage_hash + per-slot
    /// proof+value. We call this at `parent_block` to read the
    /// block-START state for the touched account.
    pub async fn account_proof(
        &self,
        addr: Address,
        slots: Vec<B256>,
        block: u64,
    ) -> Result<EIP1186AccountProofResponse> {
        self.provider
            .get_proof(addr, slots)
            .block_id(BlockId::Number(BlockNumberOrTag::Number(block)))
            .await
            .with_context(|| format!("eth_getProof({addr}) @ block {block}"))
    }

    /// `eth_getCode(addr, block)`. Used as a fallback when the
    /// prestate tracer didn't include the bytecode for an account
    /// known to have code (e.g. newly-deployed contracts).
    pub async fn code(&self, addr: Address, block: u64) -> Result<Bytes> {
        self.provider
            .get_code_at(addr)
            .block_id(BlockId::Number(BlockNumberOrTag::Number(block)))
            .await
            .with_context(|| format!("eth_getCode({addr}) @ block {block}"))
    }

    /// `eth_getBalance(addr, block)`. Used to inject pre-block balances
    /// for withdrawal recipients (the prestate tracer misses them).
    pub async fn balance(&self, addr: Address, block: u64) -> Result<alloy::primitives::U256> {
        self.provider
            .get_balance(addr)
            .block_id(BlockId::Number(BlockNumberOrTag::Number(block)))
            .await
            .with_context(|| format!("eth_getBalance({addr}) @ block {block}"))
    }

    /// `eth_getStorageAt(addr, slot, block)`. Used to inject the
    /// canonical block-start values for the Pectra system contracts'
    /// pre-allocated slots (the ring-buffer entries written by prior
    /// blocks).
    pub async fn storage_at(&self, addr: Address, slot: B256, block: u64) -> Result<B256> {
        self.provider
            .get_storage_at(addr, slot.into())
            .block_id(BlockId::Number(BlockNumberOrTag::Number(block)))
            .await
            .map(B256::from)
            .with_context(|| format!("eth_getStorageAt({addr},{slot}) @ block {block}"))
    }

    /// `eth_getTransactionCount(addr, block)` — i.e. the account's
    /// nonce. Used together with `balance` to inject withdrawal
    /// recipients into the prestate.
    pub async fn nonce(&self, addr: Address, block: u64) -> Result<u64> {
        self.provider
            .get_transaction_count(addr)
            .block_id(BlockId::Number(BlockNumberOrTag::Number(block)))
            .await
            .with_context(|| format!("eth_getTransactionCount({addr}) @ block {block}"))
    }

    /// `debug_executionWitness(block)` — Reth/Erigon. Returns the raw
    /// MPT nodes (`state`), deployed bytecodes (`codes`), and pre-image
    /// keys (`keys`, 20-byte addresses and 32-byte storage slots whose
    /// keccak appears as a key in the tries). Sufficient for stateless
    /// re-execution + state-root reconstruction including
    /// untouched-sibling leaves that share trie prefixes with our
    /// touched keys.
    pub async fn execution_witness(&self, block: u64) -> Result<ExecutionWitness> {
        let block_hex = format!("0x{block:x}");
        let v: Value = self
            .provider
            .raw_request("debug_executionWitness".into(), (block_hex,))
            .await
            .with_context(|| format!("debug_executionWitness({block})"))?;
        Ok(ExecutionWitness {
            state: decode_hex_array(&v, "state")?,
            codes: decode_hex_array(&v, "codes")?,
            keys:  decode_hex_array(&v, "keys")?,
        })
    }

    // ---- private ----------------------------------------------------------

    async fn debug_trace_prestate(&self, block: u64, diff_mode: bool) -> Result<Value> {

        let block_hex = format!("0x{block:x}");
        let config = if diff_mode {
            json!({
                "tracer": "prestateTracer",
                "tracerConfig": { "diffMode": true }
            })
        } else {
            json!({ "tracer": "prestateTracer" })
        };
        self.provider
            .raw_request(
                "debug_traceBlockByNumber".into(),
                (block_hex, config),
            )
            .await
            .with_context(|| {
                format!("debug_traceBlockByNumber({block}, diffMode={diff_mode})")
            })
    }
}

fn decode_hex_array(v: &Value, field: &'static str) -> Result<Vec<Bytes>> {
    let arr = v
        .get(field)
        .ok_or_else(|| anyhow!("witness: missing `{}` field", field))?
        .as_array()
        .ok_or_else(|| anyhow!("witness: `{}` is not an array", field))?;
    arr.iter()
        .map(|x| {
            let s = x
                .as_str()
                .ok_or_else(|| anyhow!("witness: `{}` item not string", field))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s)
                .with_context(|| format!("witness: decoding `{}` hex", field))?;
            Ok(Bytes::from(bytes))
        })
        .collect()
}

// ----- prestate parsing ----------------------------------------------------

fn merge_prestate_traces(traces_raw: &Value, first_wins: bool) -> Prestate {
    let mut out = Prestate::default();
    let Some(traces) = traces_raw.as_array() else { return out };
    // Track which addresses have been "first-seen" so we can correctly
    // snapshot block-start state from the FIRST tx that touches each
    // address — including treating omitted JSON fields as their default
    // values (the tracer omits zero balance, zero nonce, empty code).
    // Without this, a later tx that reports a modified field (e.g.
    // nonce=1 after an EIP-7702 auth bump) would erroneously become
    // our "block-start" value when the true block-start was 0.
    let mut seen: HashSet<Address> = HashSet::new();
    for tx in traces {
        // Each entry is either `{"result": {<addr>: {...}}}` or the
        // address-keyed object directly, depending on the client.
        let inner = tx.get("result").unwrap_or(tx);
        merge_one_into(&mut out, inner, first_wins, Some(&mut seen));
    }
    out
}

fn merge_one_into(
    out: &mut Prestate,
    addrs_obj: &Value,
    first_wins: bool,
    mut seen: Option<&mut HashSet<Address>>,
) {
    let Some(obj) = addrs_obj.as_object() else { return };
    for (addr_str, info) in obj {
        let Ok(addr) = addr_str.parse::<Address>() else {
            warn!(%addr_str, "skipping malformed address in prestate trace");
            continue;
        };
        // `is_first_appearance` is only meaningful for the non-diff
        // (full prestate) caller, which passes a `seen` set. The diff
        // caller (`merge_one_into(.., first_wins, None)`) doesn't track
        // first-appearance because diff JSON omits "unchanged" fields,
        // so omitted ≠ default there — only present-vs-absent matters.
        let is_first_appearance =
            seen.as_mut().map(|s| s.insert(addr)).unwrap_or(false);
        let entry = out.entry(addr).or_default();

        if is_first_appearance {
            // First tx to touch this address: snapshot the block-start
            // state. The tracer omits zero balance / zero nonce / empty
            // code from the JSON, so omission means the default value.
            entry.balance = Some(parse_u256(info.get("balance")).unwrap_or(U256::ZERO));
            entry.nonce   = Some(parse_u64(info.get("nonce")).unwrap_or(0));
            entry.code    = Some(parse_bytes(info.get("code")).unwrap_or_default());
        } else {
            if let Some(v) = parse_u256(info.get("balance")) {
                if !first_wins || entry.balance.is_none() {
                    entry.balance = Some(v);
                }
            }
            if let Some(v) = parse_u64(info.get("nonce")) {
                if !first_wins || entry.nonce.is_none() {
                    entry.nonce = Some(v);
                }
            }
            if let Some(v) = parse_bytes(info.get("code")) {
                if !first_wins || entry.code.is_none() {
                    entry.code = Some(v);
                }
            }
        }
        if let Some(stor) = info.get("storage").and_then(Value::as_object) {
            for (key_str, val_str) in stor {
                let Ok(slot)  = key_str.parse::<B256>() else { continue };
                let Some(val) = parse_b256(Some(val_str)) else { continue };
                if first_wins {
                    entry.storage.entry(slot).or_insert(val);
                } else {
                    entry.storage.insert(slot, val);
                }
            }
        }
    }
}

fn parse_u256(v: Option<&Value>) -> Option<U256> {
    v?.as_str()?.parse().ok()
}

fn parse_u64(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    // Hex string form: "0x..".
    let s = v.as_str()?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

fn parse_bytes(v: Option<&Value>) -> Option<Bytes> {
    v?.as_str()?.parse().ok()
}

fn parse_b256(v: Option<&Value>) -> Option<B256> {
    v?.as_str()?.parse().ok()
}

//! Thin alloy-based JSON-RPC client wrapper.
//!
//! Each method maps directly to the standard JSON-RPC name. The
//! returned types are alloy's typed structs (Block / Header /
//! EIP1186AccountProofResponse) so encoders can read fields directly.
//! The prestate-tracer responses are parsed via `serde_json::Value`
//! since the wire shape differs slightly between clients.
//!
//! All "address state at X" methods take a block HASH (`B256`),
//! never a number. Reasoning: between calls during a single
//! input-gen run (~10s), the upstream node may reorg; addressing by
//! number would silently let different calls resolve to different
//! canonical blocks. Pinning every call to a hash captured once at
//! startup makes a mid-run reorg either invisible (the hash still
//! resolves on a non-pruning node) or detectable (the hash is no
//! longer in the canonical chain → call errors). `block_by_number_*`
//! is the single startup-only escape hatch used to discover the
//! anchor hash itself.

use std::collections::{BTreeMap, HashSet};

use alloy::eips::{BlockId, RpcBlockHash};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::{
    Block, BlockNumberOrTag, BlockTransactionsKind, EIP1186AccountProofResponse,
};
use alloy::transports::http::{Client as HttpClient, Http};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::warn;

use crate::errors::ReorgDetected;

pub struct Client {
    provider: RootProvider<Http<HttpClient>>,
}

/// Block-start values for one account, as reported by the
/// `prestateTracer`. Fields are optional because the tracer omits
/// fields that the tx didn't touch.
///
/// Derives `Serialize`/`Deserialize` so a fully-resolved bundle of
/// these (see `offline::OfflineSources`) can be persisted to JSON
/// and replayed without re-fetching from RPC — used by the
/// `input-gen-from-manifest` binary and by the eest-runner pipeline.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountPrestate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce:   Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code:    Option<Bytes>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub storage: BTreeMap<B256, B256>,
}

pub type Prestate = BTreeMap<Address, AccountPrestate>;

/// Aggregated diff-mode result. `pre` and `post` cover only fields
/// that changed during the block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionWitness {
    pub state: Vec<Bytes>,
    pub codes: Vec<Bytes>,
    pub keys:  Vec<Bytes>,
}

/// Helper: wrap a `B256` block hash as the `BlockId` needed by
/// alloy's per-call `.block_id(...)` builders. `require_canonical`
/// is `false` so the node can answer even for a hash that's no
/// longer on the canonical chain (i.e. a reorged-out block whose
/// trie state hasn't been pruned yet) — main.rs catches that case
/// via the end-of-run reverify.
fn id(hash: B256) -> BlockId {
    BlockId::Hash(RpcBlockHash::from_hash(hash, Some(false)))
}

/// Map an `anyhow::Error` to `ReorgDetected` if its display string
/// indicates the node lost track of our anchored hash. Reth/Erigon
/// surface this as JSON-RPC error -32001 with message "block not
/// found: hash <...>"; geth uses "header not found". Either way,
/// the hash was canonical when we captured it earlier in this run,
/// so the only explanation is a reorg — convert to the typed error
/// so `main.rs` exits 75 (EX_TEMPFAIL) and `verify_blocks.py`
/// auto-retries the same block.
fn promote_not_found_to_reorg(
    err: anyhow::Error,
    hash: B256,
    phase: &'static str,
) -> anyhow::Error {
    let msg = format!("{err:#}").to_lowercase();
    if msg.contains("block not found")
        || msg.contains("header not found")
        || msg.contains("unknown block")
    {
        return ReorgDetected {
            block: 0, // we don't always know the number at this point
            expected: hash,
            actual: None,
            phase,
        }
        .into();
    }
    err
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

    /// `eth_getBlockByNumber(n, true)` — header + full canonical
    /// transaction envelopes. **Use this only once per run** to
    /// discover the canonical block hash that anchors every other
    /// call. After that, switch to `block_by_hash_full` / `block_by_hash`.
    pub async fn block_by_number_full(&self, number: u64) -> Result<Block> {
        self.provider
            .get_block_by_number(
                BlockNumberOrTag::Number(number),
                BlockTransactionsKind::Full,
            )
            .await
            .with_context(|| format!("eth_getBlockByNumber({number}, full)"))?
            .ok_or_else(|| anyhow!("block {number} not found"))
    }

    /// `eth_getBlockByHash(hash, false)` — header + tx hash list.
    /// Used for parent and earlier ancestors via parent-hash chain
    /// walking.
    pub async fn block_by_hash(&self, hash: B256) -> Result<Block> {
        self.provider
            .get_block_by_hash(hash, BlockTransactionsKind::Hashes)
            .await
            .map_err(|e| {
                promote_not_found_to_reorg(
                    anyhow::Error::from(e).context(format!("eth_getBlockByHash({hash})")),
                    hash,
                    "eth_getBlockByHash",
                )
            })?
            .ok_or_else(|| {
                // Reth returns `Ok(None)` for an unknown hash; same
                // semantic as "block not found" RPC error.
                anyhow::Error::new(ReorgDetected {
                    block: 0,
                    expected: hash,
                    actual: None,
                    phase: "eth_getBlockByHash (Ok(None))",
                })
            })
    }

    /// `eth_getBlockByHash(hash, true)` — header + full canonical
    /// transaction envelopes. Used to re-fetch the anchor block at
    /// end-of-run for the reorg reverify, and (rarely) when a caller
    /// needs full tx data for an ancestor.
    pub async fn block_by_hash_full(&self, hash: B256) -> Result<Block> {
        self.provider
            .get_block_by_hash(hash, BlockTransactionsKind::Full)
            .await
            .map_err(|e| {
                promote_not_found_to_reorg(
                    anyhow::Error::from(e).context(format!("eth_getBlockByHash({hash}, full)")),
                    hash,
                    "eth_getBlockByHash full",
                )
            })?
            .ok_or_else(|| {
                anyhow::Error::new(ReorgDetected {
                    block: 0,
                    expected: hash,
                    actual: None,
                    phase: "eth_getBlockByHash full (Ok(None))",
                })
            })
    }

    /// `debug_traceBlockByHash(hash, prestateTracer)` — non-diff
    /// mode. Returns the union of every (account → balance/nonce/code/
    /// storage) the block's txs touched, with **block-start** values
    /// (i.e. the first observed value per (addr, slot) wins across
    /// the per-tx traces).
    pub async fn prestate_by_hash(&self, hash: B256) -> Result<Prestate> {
        let raw = self.debug_trace_prestate_by_hash(hash, false).await?;
        Ok(merge_prestate_traces(&raw, /*first_wins=*/ true))
    }

    /// `debug_traceBlockByHash(hash, prestateTracer, diffMode=true)`.
    /// Returns aggregated `pre` and `post` maps covering only the
    /// fields that changed during the block.
    pub async fn prestate_diff_by_hash(&self, hash: B256) -> Result<PrestateDiff> {
        let raw = self.debug_trace_prestate_by_hash(hash, true).await?;
        let traces = raw
            .as_array()
            .ok_or_else(|| anyhow!("debug_traceBlockByHash: expected array"))?;
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

    /// `eth_getProof(addr, slots)` pinned to `hash`. Returns the
    /// canonical block-end balance/nonce/code_hash/storage_hash +
    /// per-slot proof+value. We call this at the parent block hash to
    /// read the block-START state for the touched account.
    pub async fn account_proof_at_hash(
        &self,
        addr: Address,
        slots: Vec<B256>,
        hash: B256,
    ) -> Result<EIP1186AccountProofResponse> {
        self.provider
            .get_proof(addr, slots)
            .block_id(id(hash))
            .await
            .map_err(|e| {
                promote_not_found_to_reorg(
                    anyhow::Error::from(e).context(format!("eth_getProof({addr}) @ {hash}")),
                    hash,
                    "eth_getProof",
                )
            })
    }

    /// `eth_getCode(addr)` pinned to `hash`. Used as a fallback when
    /// the prestate tracer didn't include the bytecode for an account
    /// known to have code (e.g. newly-deployed contracts).
    pub async fn code_at_hash(&self, addr: Address, hash: B256) -> Result<Bytes> {
        self.provider
            .get_code_at(addr)
            .block_id(id(hash))
            .await
            .map_err(|e| {
                promote_not_found_to_reorg(
                    anyhow::Error::from(e).context(format!("eth_getCode({addr}) @ {hash}")),
                    hash,
                    "eth_getCode",
                )
            })
    }

    /// `eth_getBalance(addr)` pinned to `hash`. Used to inject
    /// pre-block balances for withdrawal recipients (the prestate
    /// tracer misses them).
    pub async fn balance_at_hash(&self, addr: Address, hash: B256) -> Result<U256> {
        self.provider
            .get_balance(addr)
            .block_id(id(hash))
            .await
            .map_err(|e| {
                promote_not_found_to_reorg(
                    anyhow::Error::from(e).context(format!("eth_getBalance({addr}) @ {hash}")),
                    hash,
                    "eth_getBalance",
                )
            })
    }

    /// `eth_getStorageAt(addr, slot)` pinned to `hash`. Used to
    /// inject the canonical block-start values for the Pectra system
    /// contracts' pre-allocated slots (the ring-buffer entries written
    /// by prior blocks).
    pub async fn storage_at_hash(
        &self,
        addr: Address,
        slot: B256,
        hash: B256,
    ) -> Result<B256> {
        self.provider
            .get_storage_at(addr, slot.into())
            .block_id(id(hash))
            .await
            .map(B256::from)
            .map_err(|e| {
                promote_not_found_to_reorg(
                    anyhow::Error::from(e)
                        .context(format!("eth_getStorageAt({addr},{slot}) @ {hash}")),
                    hash,
                    "eth_getStorageAt",
                )
            })
    }

    /// `eth_getTransactionCount(addr)` pinned to `hash` — i.e. the
    /// account's nonce. Used together with `balance_at_hash` to
    /// inject withdrawal recipients into the prestate.
    pub async fn nonce_at_hash(&self, addr: Address, hash: B256) -> Result<u64> {
        self.provider
            .get_transaction_count(addr)
            .block_id(id(hash))
            .await
            .map_err(|e| {
                promote_not_found_to_reorg(
                    anyhow::Error::from(e)
                        .context(format!("eth_getTransactionCount({addr}) @ {hash}")),
                    hash,
                    "eth_getTransactionCount",
                )
            })
    }

    /// Execution witness for a block, pinned to `hash`.
    ///
    /// Returns the raw MPT nodes (`state`), deployed bytecodes
    /// (`codes`), and pre-image keys (`keys`). Sufficient for
    /// stateless re-execution + state-root reconstruction.
    ///
    /// reth (≤ this project's compatible range) only exposes
    /// `debug_executionWitness(block_number)` — no `*ByHash`
    /// variant exists. We bracket the by-number call with two
    /// hash lookups: resolve `hash → number` immediately before,
    /// and re-confirm `number → hash` immediately after. If the
    /// canonical chain at `number` ever resolves to a different
    /// hash, we surface `ReorgDetected` instead of returning data
    /// from a stale fork.
    pub async fn execution_witness_by_hash(&self, hash: B256) -> Result<ExecutionWitness> {
        // (a) Resolve hash → number. Confirms the hash is on the
        // canonical chain right now; if the node already pruned this
        // side branch we'll get "block not found", which we elevate
        // to ReorgDetected so the caller retries cleanly.
        let pre = self
            .provider
            .get_block_by_hash(hash, BlockTransactionsKind::Hashes)
            .await
            .map_err(|e| {
                promote_not_found_to_reorg(
                    anyhow::Error::from(e)
                        .context(format!("eth_getBlockByHash({hash}) pre-witness")),
                    hash,
                    "pre-witness block_by_hash",
                )
            })?
            .ok_or_else(|| {
                anyhow::Error::new(ReorgDetected {
                    block: 0,
                    expected: hash,
                    actual: None,
                    phase: "pre-witness block_by_hash (Ok(None))",
                })
            })?;
        let number = pre.header.number;

        // (b) Issue the by-number witness call.
        let block_hex = format!("0x{number:x}");
        let v: Value = self
            .provider
            .raw_request("debug_executionWitness".into(), (block_hex,))
            .await
            .map_err(|e| {
                promote_not_found_to_reorg(
                    anyhow::Error::from(e)
                        .context(format!("debug_executionWitness({number})")),
                    hash,
                    "debug_executionWitness",
                )
            })?;

        // (c) Re-confirm canonical block at `number` still has our hash.
        let post = self
            .provider
            .get_block_by_number(
                BlockNumberOrTag::Number(number),
                BlockTransactionsKind::Hashes,
            )
            .await
            .with_context(|| format!("eth_getBlockByNumber({number}) post-witness"))?
            .ok_or_else(|| ReorgDetected {
                block: number,
                expected: hash,
                actual: None,
                phase: "post-witness eth_getBlockByNumber",
            })?;
        if post.header.hash != hash {
            return Err(ReorgDetected {
                block: number,
                expected: hash,
                actual: Some(post.header.hash),
                phase: "post-witness hash drifted",
            }
            .into());
        }

        Ok(ExecutionWitness {
            state: decode_hex_array(&v, "state")?,
            codes: decode_hex_array(&v, "codes")?,
            keys:  decode_hex_array(&v, "keys")?,
        })
    }

    /// Query EIP-7910 `eth_config` to learn whether the chain's current
    /// (latest) fork is Osaka-or-later, and if so its activation time.
    ///
    /// Detection is fork-name-independent: `eth_config` exposes a fork-id
    /// *hash*, not a name, so we key off the P256VERIFY precompile
    /// (EIP-7951, address `0x..0100`) that Osaka/Fusaka introduces.
    /// Returns the current fork's `activationTime` iff that precompile is
    /// present — a block is Osaka iff its timestamp is `>=` that value.
    ///
    /// Best-effort: any RPC / shape error returns `Ok(None)`, so the
    /// caller treats the block as pre-Osaka. This preserves behaviour on
    /// nodes that don't implement `eth_config`.
    ///
    /// Note: keyed off the *current* fork, so once a hypothetical
    /// post-Osaka fork ships, blocks in the Osaka..next window would be
    /// misclassified as pre-Osaka. Revisit when evmone gains a later
    /// revision (none exists today).
    pub async fn osaka_activation_time(&self) -> Result<Option<u64>> {
        let v: Value = match self.provider.raw_request("eth_config".into(), ()).await {
            Ok(v) => v,
            Err(e) => {
                warn!(err = %e, "eth_config unavailable; treating block as pre-Osaka");
                return Ok(None);
            }
        };
        let Some(current) = v.get("current") else {
            return Ok(None);
        };
        const P256VERIFY: &str = "0x0000000000000000000000000000000000000100";
        let has_p256 = current
            .get("precompiles")
            .and_then(Value::as_object)
            .map(|m| m.values().any(|a| a.as_str() == Some(P256VERIFY)))
            .unwrap_or(false);
        if !has_p256 {
            return Ok(None);
        }
        Ok(parse_u64(current.get("activationTime")))
    }

    // ---- private ----------------------------------------------------------

    async fn debug_trace_prestate_by_hash(
        &self,
        hash: B256,
        diff_mode: bool,
    ) -> Result<Value> {
        let hash_hex = format!("0x{:x}", hash);
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
                "debug_traceBlockByHash".into(),
                (hash_hex, config),
            )
            .await
            .map_err(|e| {
                promote_not_found_to_reorg(
                    anyhow::Error::from(e).context(format!(
                        "debug_traceBlockByHash({hash}, diffMode={diff_mode})"
                    )),
                    hash,
                    if diff_mode {
                        "debug_traceBlockByHash (diff)"
                    } else {
                        "debug_traceBlockByHash"
                    },
                )
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

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

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::mpt::{self, Lookup};

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

/// Aggregated view of the state touched by a block. All addresses and storage
/// slots are lower-case `0x…` hex strings.
#[derive(Debug, Default)]
pub struct StateAccess {
    /// Accounts whose prestate was read (balance / nonce / code).
    pub accounts_read: BTreeSet<String>,
    /// Accounts whose balance, nonce or code changed.
    pub accounts_written: BTreeSet<String>,
    /// Accounts whose `code` field appeared in the prestate (contracts read).
    pub contracts_read: BTreeSet<String>,
    /// Accounts whose `code` field changed (contracts deployed / self-destructed).
    pub contracts_written: BTreeSet<String>,
    /// Storage slots read: address -> set of slot keys.
    pub storage_read: BTreeMap<String, BTreeSet<String>>,
    /// Storage slots written: address -> set of slot keys.
    pub storage_written: BTreeMap<String, BTreeSet<String>>,
}

impl StateAccess {
    pub fn print_summary(&self) {
        println!("─── State access summary ───");
        println!("  accounts read     : {}", self.accounts_read.len());
        println!("  accounts written  : {}", self.accounts_written.len());
        println!("  contracts read    : {}", self.contracts_read.len());
        println!("  contracts written : {}", self.contracts_written.len());
        let storage_read_total: usize = self.storage_read.values().map(|s| s.len()).sum();
        let storage_written_total: usize = self.storage_written.values().map(|s| s.len()).sum();
        println!(
            "  storage slots read    : {} (across {} accounts)",
            storage_read_total,
            self.storage_read.len()
        );
        println!(
            "  storage slots written : {} (across {} accounts)",
            storage_written_total,
            self.storage_written.len()
        );

        let show = 5usize;
        println!("  first {show} accounts read:");
        for a in self.accounts_read.iter().take(show) {
            println!("    {a}");
        }
        println!("  first {show} accounts written:");
        for a in self.accounts_written.iter().take(show) {
            println!("    {a}");
        }
        println!("  first {show} storage-read entries:");
        for (a, slots) in self.storage_read.iter().take(show) {
            println!("    {a} -> {} slot(s)", slots.len());
            for s in slots.iter().take(3) {
                println!("      {s}");
            }
        }
        println!("  first {show} storage-written entries:");
        for (a, slots) in self.storage_written.iter().take(show) {
            println!("    {a} -> {} slot(s)", slots.len());
            for s in slots.iter().take(3) {
                println!("      {s}");
            }
        }
    }
}

/// Raw execution witness as returned by `debug_executionWitness`. Each field
/// is an array of opaque hex blobs in the on-wire response; we keep them as
/// raw bytes in the order received.
#[derive(Debug, Default)]
pub struct ExecutionWitness {
    /// MPT (or SMT) intermediary nodes (RLP-encoded).
    pub state_nodes: Vec<Vec<u8>>,
    /// Contract bytecodes.
    pub codes: Vec<Vec<u8>>,
    /// Trie key preimages (addresses / storage slots).
    pub keys: Vec<Vec<u8>>,
    /// Ancestor block headers (RLP-encoded).
    pub headers: Vec<Vec<u8>>,
}

impl ExecutionWitness {
    pub fn print_summary(&self) {
        println!("─── Execution witness summary ───");
        println!("  trie nodes : {}", self.state_nodes.len());
        println!("  bytecodes  : {}", self.codes.len());
        println!("  keys       : {}", self.keys.len());
        println!("  headers    : {}", self.headers.len());
        let nodes_bytes: usize = self.state_nodes.iter().map(|v| v.len()).sum();
        let code_bytes: usize = self.codes.iter().map(|v| v.len()).sum();
        println!("  total node bytes : {nodes_bytes}");
        println!("  total code bytes : {code_bytes}");
    }
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

    async fn storage_at(&self, addr: &str, slot: &str, block_number: u64) -> Result<String> {
        let block_hex = format!("0x{block_number:x}");
        let v = self
            .call("eth_getStorageAt", json!([addr, slot, block_hex]))
            .await?;
        Ok(v.as_str().unwrap_or("0x").to_string())
    }

    /// Capture and print every system-level state change in the block (the
    /// edits that `debug_traceBlockByNumber` cannot see): the four post-
    /// Pectra system contracts (EIP-4788, 2935, 7002, 7251) and beacon-chain
    /// withdrawals. Storage diffs are queried for slots the witness merge
    /// already attributed; withdrawals come straight from the block header.
    pub async fn print_system_modifications(
        &self,
        block_number: u64,
        access: &StateAccess,
    ) -> Result<()> {
        const SYS_CONTRACTS: &[(&str, &str)] = &[
            ("0x000f3df6d732807ef1319fb7b8bb8522d0beac02", "EIP-4788 beacon roots         (pre-block)"),
            ("0x0000f90827f1c53a10cb7a02335b175320002935", "EIP-2935 block hashes         (pre-block)"),
            ("0x00000961ef480eb55e80d19ad83579a64c007002", "EIP-7002 withdrawal requests  (post-block)"),
            ("0x0000bbddc7ce488642fb579f8b00f3a590007251", "EIP-7251 consolidation requests (post-block)"),
        ];

        // Fetch current block (for coinbase + withdrawals).
        let block_hex = format!("0x{block_number:x}");
        let block = self
            .call("eth_getBlockByNumber", json!([block_hex, false]))
            .await?;
        let coinbase = block.get("miner").and_then(Value::as_str).unwrap_or("?");

        println!("─── System modifications ───");
        println!("  coinbase           : {coinbase}");

        for (addr, label) in SYS_CONTRACTS {
            println!("  {label}");
            println!("    address          : {addr}");
            let slots = match access.storage_written.get(*addr) {
                Some(s) if !s.is_empty() => s,
                _ => {
                    println!("    (no storage writes attributed by witness merge)");
                    continue;
                }
            };
            for slot in slots {
                let pre = self.storage_at(addr, slot, block_number.saturating_sub(1)).await?;
                let post = self.storage_at(addr, slot, block_number).await?;
                let marker = if pre != post { "  ← CHANGED" } else { "" };
                println!("    slot {slot}");
                println!("       pre  = {pre}");
                println!("       post = {post}{marker}");
            }
        }

        // Withdrawals: list of {index, validatorIndex, address, amount(gwei)}.
        let empty_withdrawals = Vec::new();
        let withdrawals = block
            .get("withdrawals")
            .and_then(Value::as_array)
            .unwrap_or(&empty_withdrawals);
        if withdrawals.is_empty() {
            println!("  Beacon withdrawals (post-block): (none)");
        } else {
            // Aggregate gwei per recipient.
            let mut by_addr: BTreeMap<String, u64> = BTreeMap::new();
            let mut count_by_addr: BTreeMap<String, usize> = BTreeMap::new();
            for w in withdrawals {
                let addr = w
                    .get("address")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_lowercase();
                let amount_hex = w.get("amount").and_then(Value::as_str).unwrap_or("0x0");
                let amount = u64::from_str_radix(amount_hex.strip_prefix("0x").unwrap_or("0"), 16)
                    .unwrap_or(0);
                *by_addr.entry(addr.clone()).or_insert(0) += amount;
                *count_by_addr.entry(addr).or_insert(0) += 1;
            }
            println!(
                "  Beacon withdrawals (post-block): {} entries, {} unique recipients",
                withdrawals.len(),
                by_addr.len()
            );
            for (addr, total_gwei) in &by_addr {
                let count = count_by_addr.get(addr).copied().unwrap_or(0);
                let total_wei = (*total_gwei as u128) * 1_000_000_000;
                let eth = (*total_gwei as f64) / 1e9;
                println!(
                    "    {addr}  ×{count}  +{total_gwei} gwei  (={total_wei} wei, ≈ {eth:.9} ETH)"
                );
            }
        }
        Ok(())
    }

    /// Fetch the parent block's `stateRoot` (used as the trie root for
    /// walking the execution witness).
    pub async fn parent_state_root(&self, block_number: u64) -> Result<[u8; 32]> {
        if block_number == 0 {
            return Err(anyhow!("cannot fetch parent of block 0"));
        }
        let parent_hex = format!("0x{:x}", block_number - 1);
        let result = self
            .call("eth_getBlockByNumber", json!([parent_hex, false]))
            .await?;
        let root_str = result
            .get("stateRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("parent block missing stateRoot"))?;
        let bytes = hex_decode(root_str)?;
        if bytes.len() != 32 {
            return Err(anyhow!("parent stateRoot is {} bytes, want 32", bytes.len()));
        }
        Ok(<[u8; 32]>::try_from(bytes.as_slice()).unwrap())
    }

    /// Aggregate read / written accounts and storage slots across all
    /// transactions in the block. Requires two `debug_traceBlockByNumber`
    /// calls with `prestateTracer`:
    ///   * non-diff mode → every account / slot touched (the read set)
    ///   * diff mode     → every account / slot whose value changed; in diff
    ///                     mode same-value reads are absent, so anything that
    ///                     appears in `pre` *or* `post` is a write.
    ///
    /// Then merges the `witness.keys` preimages: anything that appears in
    /// the witness but was missed by the per-tx tracer (system pre/post
    /// hooks: EIP-4788 / 2935 / 7002 / 7251, beacon withdrawals) is
    /// attributed by walking the witness state trie and added to the
    /// `*_written` sets.
    pub async fn fetch_state_access(
        &self,
        block_number: u64,
        witness: &ExecutionWitness,
    ) -> Result<StateAccess> {
        let block_hex = format!("0x{block_number:x}");
        let mut acc = StateAccess::default();

        // Pass 1: full prestate (no diff mode) → reads.
        let read_cfg = json!({ "tracer": "prestateTracer" });
        let result = self
            .call("debug_traceBlockByNumber", json!([block_hex, read_cfg]))
            .await?;
        let traces = result
            .as_array()
            .ok_or_else(|| anyhow!("debug_traceBlockByNumber: expected array, got {result}"))?;
        for tx in traces {
            // Each entry is either `{ "result": { ... } }` or directly the
            // address-keyed object, depending on the client. Handle both.
            let inner = tx.get("result").unwrap_or(tx);
            let Some(accessed) = inner.as_object() else { continue };
            for (addr, info) in accessed {
                let addr = addr.to_lowercase();
                acc.accounts_read.insert(addr.clone());
                if info.get("code").and_then(Value::as_str).is_some_and(|c| c != "0x") {
                    acc.contracts_read.insert(addr.clone());
                }
                if let Some(storage) = info.get("storage").and_then(Value::as_object) {
                    let entry = acc.storage_read.entry(addr).or_default();
                    for key in storage.keys() {
                        entry.insert(key.to_lowercase());
                    }
                }
            }
        }

        // Pass 2: diff mode → writes (pre ∪ post; both sides represent
        // entries whose value changed, so either side is a write).
        let diff_cfg = json!({
            "tracer": "prestateTracer",
            "tracerConfig": { "diffMode": true },
        });
        let result = self
            .call("debug_traceBlockByNumber", json!([block_hex, diff_cfg]))
            .await?;
        let traces = result
            .as_array()
            .ok_or_else(|| anyhow!("debug_traceBlockByNumber: expected array, got {result}"))?;
        for tx in traces {
            let inner = tx.get("result").unwrap_or(tx);
            for section in ["pre", "post"] {
                let Some(entries) = inner.get(section).and_then(Value::as_object) else {
                    continue;
                };
                for (addr, info) in entries {
                    let addr = addr.to_lowercase();
                    acc.accounts_written.insert(addr.clone());
                    if info.get("code").is_some() {
                        acc.contracts_written.insert(addr.clone());
                    }
                    if let Some(storage) = info.get("storage").and_then(Value::as_object) {
                        let entry = acc.storage_written.entry(addr).or_default();
                        for key in storage.keys() {
                            entry.insert(key.to_lowercase());
                        }
                    }
                }
            }
        }

        // Fold in witness-only accesses. The per-tx tracer is blind to
        // block-level system calls (EIP-4788 / 2935 / 7002 / 7251) and to
        // beacon-chain withdrawals, but the witness covers all of them.
        // For every preimage in `witness.keys` that the tracer missed,
        // walk the witness trie to attribute it and classify it as written.
        let parent_state_root = self.parent_state_root(block_number).await?;
        merge_witness_keys(&mut acc, witness, parent_state_root)?;

        // Make the read sets strictly read-only: anything that was written is
        // not "read" in the read-only sense, even if its prestate was loaded.
        for addr in &acc.accounts_written {
            acc.accounts_read.remove(addr);
        }
        for addr in &acc.contracts_written {
            acc.contracts_read.remove(addr);
        }
        for (addr, written_slots) in &acc.storage_written {
            if let Some(read_slots) = acc.storage_read.get_mut(addr) {
                for slot in written_slots {
                    read_slots.remove(slot);
                }
            }
        }
        acc.storage_read.retain(|_, slots| !slots.is_empty());

        Ok(acc)
    }

    /// Fetch the execution witness (trie nodes + bytecodes) for a block.
    pub async fn fetch_execution_witness(&self, block_number: u64) -> Result<ExecutionWitness> {
        let block_hex = format!("0x{block_number:x}");
        let result = self
            .call("debug_executionWitness", json!([block_hex]))
            .await?;

        let mut w = ExecutionWitness::default();

        // Reth/Geth shape: { "state": ["0x..", ...], "codes": [...], "keys": [...], "headers": [...] }
        // Older clients exposed objects keyed by hash; we only support the array form.
        w.state_nodes = decode_hex_array(result.get("state"), "state")?;
        w.codes = decode_hex_array(result.get("codes"), "codes")?;
        w.keys = decode_hex_array(result.get("keys"), "keys")?;
        w.headers = decode_hex_array(result.get("headers"), "headers")?;
        Ok(w)
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

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).with_context(|| format!("decoding hex blob (len={})", s.len()))
}

/// Add witness-only preimages to `acc.{accounts,storage}_written`.
///
/// `witness.keys` is a flat list of 20-byte addresses and 32-byte slot keys
/// with no mapping between them. Address attribution is trivial (we just
/// check whether each address is already in `acc`). Slot attribution
/// requires figuring out which contract's storage trie a slot belongs to.
/// We do that by walking the witness state trie: a slot key belongs to a
/// contract iff the contract's storage trie has a proven path for
/// `keccak256(slot)`. The witness contains a full path through the trie iff
/// that (address, slot) pair was touched during execution, so this is a
/// reliable signal.
fn merge_witness_keys(
    acc: &mut StateAccess,
    witness: &ExecutionWitness,
    state_root: [u8; 32],
) -> Result<()> {
    // Build a hash-keyed node store from the witness state nodes.
    let mut nodes: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(witness.state_nodes.len());
    for node in &witness.state_nodes {
        nodes.insert(mpt::keccak256(node), node.clone());
    }

    // Separate address vs slot preimages.
    let mut addrs: Vec<Vec<u8>> = Vec::new();
    let mut slots: Vec<Vec<u8>> = Vec::new();
    for k in &witness.keys {
        match k.len() {
            20 => addrs.push(k.clone()),
            32 => slots.push(k.clone()),
            _ => {} // unexpected length; skip silently
        }
    }

    // 1. Walk each witness address to get its storageRoot (when it exists).
    //    Build address → storageRoot mapping; record addresses we'd attribute
    //    as freshly "written" if absent from the prestate-derived sets.
    // Two lists: storage roots of addresses that were ALREADY in the
    // prestate (`prestate_roots`) and storage roots of addresses we just
    // added from witness.keys (`witness_only_roots`). Try witness-only
    // first when attributing slots, since unattributed slots almost
    // certainly belong to them (system contracts / new addresses).
    let mut prestate_roots: Vec<(Vec<u8>, [u8; 32])> = Vec::new();
    let mut witness_only_roots: Vec<(Vec<u8>, [u8; 32])> = Vec::new();
    for addr in &addrs {
        let key = format!("0x{}", hex::encode(addr));
        let is_new = !acc.accounts_read.contains(&key) && !acc.accounts_written.contains(&key);
        if is_new {
            acc.accounts_written.insert(key.clone());
        }
        if let Lookup::Found(leaf_value) = mpt::lookup(&nodes, state_root, addr)? {
            let storage_root = mpt::account_storage_root(leaf_value)?;
            if is_new {
                witness_only_roots.push((addr.clone(), storage_root));
            } else {
                prestate_roots.push((addr.clone(), storage_root));
            }
        }
    }

    // 2. For each slot key, find which contract's storage trie has its path
    //    proven in the witness. First slot to match wins; ties are vanishingly
    //    unlikely because the EVM only traces (address, slot) pairs that were
    //    actually accessed.
    let empty_root: [u8; 32] = mpt::keccak256(&[0x80]); // keccak(rlp("")) = empty MPT root
    for slot in &slots {
        let slot_key = format!("0x{}", hex::encode(slot));
        // Skip slots already attributed via prestate (read or written).
        let already_known = acc
            .storage_read
            .values()
            .any(|s| s.contains(&slot_key))
            || acc
                .storage_written
                .values()
                .any(|s| s.contains(&slot_key));
        if already_known {
            continue;
        }
        // First pass: try witness-only addresses (system contracts etc.).
        // Second pass: fall back to prestate addresses. In both passes,
        // any `Lookup::Found | Absent` (i.e., a *complete* path in that
        // trie) counts as a match; `NotInWitness` means this trie wasn't
        // touched at this slot's path and we should try the next one.
        let mut matched = false;
        for candidates in [&witness_only_roots, &prestate_roots] {
            if matched {
                break;
            }
            for (owner, storage_root) in candidates {
                if *storage_root == empty_root {
                    continue;
                }
                match mpt::lookup(&nodes, *storage_root, slot)? {
                    Lookup::Found(_) | Lookup::Absent => {
                        let addr_key = format!("0x{}", hex::encode(owner));
                        acc.storage_written
                            .entry(addr_key)
                            .or_default()
                            .insert(slot_key.clone());
                        matched = true;
                        break;
                    }
                    Lookup::NotInWitness => continue,
                }
            }
        }
    }

    Ok(())
}

fn decode_hex_array(v: Option<&Value>, field: &str) -> Result<Vec<Vec<u8>>> {
    let Some(v) = v else { return Ok(Vec::new()) };
    let arr = v
        .as_array()
        .ok_or_else(|| anyhow!("debug_executionWitness: `{field}` is not an array"))?;
    arr.iter()
        .map(|item| {
            let s = item
                .as_str()
                .ok_or_else(|| anyhow!("`{field}` entry is not a hex string: {item}"))?;
            hex_decode(s)
        })
        .collect()
}

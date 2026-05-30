//! EEST + reth execution output → `ManifestSources`.
//!
//! Builds the `Block`-shaped fields as raw `serde_json::Value` to
//! avoid alloy 2.x → alloy 0.8 typed-struct mismatches across the
//! manifest boundary (the wire format — Ethereum JSON-RPC — is
//! stable across alloy major versions; only the typed wrappers
//! diverge).

use std::collections::{BTreeMap, BTreeSet};

use alloy_consensus::BlockHeader as _;
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, U256};
use anyhow::Result;
use reth_ethereum_primitives::Block as RethBlock;
use reth_primitives_traits::{Block as _, NodePrimitives, RecoveredBlock};
use revm::database::BundleState;
use serde_json::json;
use serde_json::Value;

use crate::executor::ExecutedBlock;
use crate::fixture::{Account as EestAccount, BlockchainTest, Header as EestHeader};
use crate::manifest::{
    AccountPrestate, ExecutionWitness as ManifestExecutionWitness, ManifestSources, Prestate,
    PrestateDiff,
};

// ===== top-level entry =================================================

/// Build one `ManifestSources` per fixture block. Returns Vec
/// aligned with `test.blocks` / `executed`.
pub fn manifests_for_fixture(
    test: &BlockchainTest,
    executed: &[ExecutedBlock],
) -> Result<Vec<ManifestSources>> {
    assert_eq!(test.blocks.len(), executed.len());

    let mut out = Vec::with_capacity(executed.len());

    // Running pre-block state. Starts from EEST.pre; mutates with
    // each block's BundleState as we iterate forward.
    let mut running_prestate: Prestate = test
        .pre
        .iter()
        .map(|(addr, acc)| (*addr, eest_account_to_prestate(acc)))
        .collect();

    // Genesis Block-value, used as ancestors[end] for block 0.
    let genesis_value = eest_header_to_block_value(&test.genesis_block_header, &[]);

    // ancestors[i] grows oldest-first as we process blocks.
    let mut ancestor_chain: Vec<Value> = vec![genesis_value];

    for (i, exec) in executed.iter().enumerate() {
        // (a) Snapshot pre-block state BEFORE applying this block's
        //     mutations, FILTERED to only addresses reth actually
        //     touched. EEST `pre` may include accounts the EVM
        //     never accesses; their MPT-leaf nodes aren't in the
        //     witness, so cpp-guest's verifier can't walk to them.
        let touched: BTreeSet<Address> = exec
            .witness
            .keys
            .iter()
            .filter(|k| k.len() == 20)
            .map(|k| Address::from_slice(k))
            .collect();
        let mut prestate: Prestate = running_prestate
            .iter()
            .filter(|(addr, _)| touched.contains(*addr))
            .map(|(addr, acc)| (*addr, acc.clone()))
            .collect();
        // Also include every address from this block's BundleState
        // (these were created or written during execution and may
        // not have been in EEST.pre).
        for addr in exec.bundle_state.state.keys() {
            prestate
                .entry(*addr)
                .or_insert_with(|| running_prestate.get(addr).cloned().unwrap_or_default());
        }

        // (b) Per-block diff from BundleState.
        let diff = bundle_state_to_diff(&exec.bundle_state);

        // (c) Current Block (JSON shape).
        let current = reth_block_to_value(&exec.block);

        // (d) Parent = last entry of ancestor_chain (before adding
        //     current to it).
        let parent = ancestor_chain
            .last()
            .expect("ancestor chain non-empty")
            .clone();

        // (e) System-contract slots: produce both the (addr, slot)
        //     set (which marks them writable in the Storages
        //     section) AND inject each slot's parent-block value
        //     into `prestate[addr].storage`. Mirrors
        //     `inject_system_contracts` in rust-input-gen's
        //     online path — cpp-guest's `pre_execute_block` SLOADs
        //     these slots and fatals if they're not pre-registered
        //     in the Storages table.
        let header = exec.block.header();
        let system_contract_slots =
            system_contract_slots(header.number(), header.timestamp());
        for (sc_addr, slot) in &system_contract_slots {
            let entry = prestate.entry(*sc_addr).or_default();
            entry.storage.entry(*slot).or_insert(B256::ZERO);
            // Also inject baseline account info if missing.
            if entry.balance.is_none() {
                entry.balance = Some(U256::ZERO);
            }
            if entry.nonce.is_none() {
                entry.nonce = Some(0);
            }
        }

        // (e') Ensure every (addr, slot) that the EVM TOUCHED is
        //      registered in prestate with its block-start value.
        //      The diff carries this directly: diff.pre[addr]
        //      .storage[slot] = original_value just before the
        //      block. cpp-guest's Storages::index_of fatals on
        //      missing slots, so any storage the EVM read or wrote
        //      must be pre-populated. (Mirrors what the prestate
        //      tracer does in rust-input-gen's online path.)
        for (addr, pre_acc) in &diff.pre {
            let entry = prestate.entry(*addr).or_default();
            if entry.balance.is_none() {
                entry.balance = pre_acc.balance;
            }
            if entry.nonce.is_none() {
                entry.nonce = pre_acc.nonce;
            }
            for (slot, val) in &pre_acc.storage {
                entry.storage.entry(*slot).or_insert(*val);
            }
        }

        // (f) Witness — direct field rename.
        let witness = ManifestExecutionWitness {
            state: exec.witness.state.clone(),
            codes: exec.witness.codes.clone(),
            keys: exec.witness.keys.clone(),
        };

        // (g) ancestors latest-first (rust-input-gen's convention:
        //     ancestors[0] = parent).
        let mut ancestors = ancestor_chain.clone();
        ancestors.reverse();

        out.push(ManifestSources {
            current: current.clone(),
            parent,
            ancestors,
            prestate,
            diff,
            witness,
            system_contract_slots,
        });

        // (h) Apply post-state to running_prestate for the next iter.
        apply_bundle_to_prestate(&mut running_prestate, &exec.bundle_state);

        // (i) Push current into ancestor chain (oldest-first).
        ancestor_chain.push(current);
    }

    Ok(out)
}

// ===== BundleState → prestate / diff helpers ===========================

fn bundle_state_to_diff(bs: &BundleState) -> PrestateDiff {
    let mut diff = PrestateDiff::default();
    for (addr, bundle_acc) in &bs.state {
        let mut pre = AccountPrestate::default();
        let mut post = AccountPrestate::default();

        if let Some(orig) = &bundle_acc.original_info {
            pre.balance = Some(orig.balance);
            pre.nonce = Some(orig.nonce);
        }
        if let Some(now) = &bundle_acc.info {
            post.balance = Some(now.balance);
            post.nonce = Some(now.nonce);
        }

        for (slot_u256, slot) in &bundle_acc.storage {
            let key = B256::from(slot_u256.to_be_bytes::<32>());
            pre.storage.insert(key, B256::from(slot.original_value().to_be_bytes::<32>()));
            post.storage.insert(key, B256::from(slot.present_value().to_be_bytes::<32>()));
        }

        diff.pre.insert(*addr, pre);
        diff.post.insert(*addr, post);
    }
    diff
}

fn apply_bundle_to_prestate(running: &mut Prestate, bs: &BundleState) {
    for (addr, bundle_acc) in &bs.state {
        if bundle_acc.info.is_none() {
            running.remove(addr);
            continue;
        }
        let entry = running.entry(*addr).or_default();
        if let Some(now) = &bundle_acc.info {
            entry.balance = Some(now.balance);
            entry.nonce = Some(now.nonce);
        }
        for (slot_u256, slot) in &bundle_acc.storage {
            let key = B256::from(slot_u256.to_be_bytes::<32>());
            entry
                .storage
                .insert(key, B256::from(slot.present_value().to_be_bytes::<32>()));
        }
    }
}

fn eest_account_to_prestate(acc: &EestAccount) -> AccountPrestate {
    AccountPrestate {
        balance: Some(acc.balance),
        nonce: Some(acc.nonce.try_into().unwrap_or(0)),
        code: Some(acc.code.clone()).filter(|c| !c.is_empty()),
        storage: acc
            .storage
            .iter()
            .map(|(k, v)| (B256::from(k.to_be_bytes::<32>()), B256::from(v.to_be_bytes::<32>())))
            .collect(),
    }
}

// ===== Reth block → JSON-RPC `Block` Value =============================

fn reth_block_to_value(rb: &RecoveredBlock<RethBlock>) -> Value {
    let header = rb.header();
    let hash = rb.hash();

    // Transactions as full RPC objects: encode each signed tx to
    // RLP, decode back into alloy 2.x's `TxEnvelope` (the default),
    // serialize, then layer in block-context fields. Going through
    // RLP avoids version-specific envelope-type quirks.
    let tx_array: Vec<Value> = rb
        .body()
        .transactions
        .iter()
        .zip(rb.senders())
        .enumerate()
        .map(|(idx, (signed, &from))| {
            let raw = signed.encoded_2718();
            let envelope =
                alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_slice())
                    .expect("re-decode tx envelope");
            let mut v = serde_json::to_value(&envelope).expect("serialize tx envelope");
            if let Value::Object(m) = &mut v {
                m.insert("blockHash".into(), json!(hex(&hash.0)));
                m.insert("blockNumber".into(), json!(u64_hex(header.number())));
                m.insert("transactionIndex".into(), json!(u64_hex(idx as u64)));
                m.insert("from".into(), json!(hex(&from.0 .0)));
            }
            v
        })
        .collect();

    let mut block = json!({
        "hash": hex(&hash.0),
        "parentHash": hex(&header.parent_hash().0),
        "sha3Uncles": hex(&header.ommers_hash().0),
        "miner": hex(&header.beneficiary().0 .0),
        "stateRoot": hex(&header.state_root().0),
        "transactionsRoot": hex(&header.transactions_root().0),
        "receiptsRoot": hex(&header.receipts_root().0),
        "logsBloom": hex(header.logs_bloom().0.as_slice()),
        "difficulty": u256_hex(&header.difficulty()),
        "number": u64_hex(header.number()),
        "gasLimit": u64_hex(header.gas_limit()),
        "gasUsed": u64_hex(header.gas_used()),
        "timestamp": u64_hex(header.timestamp()),
        "extraData": format!("0x{}", hex::encode(header.extra_data())),
        "mixHash": hex(&header.mix_hash().unwrap_or_default().0),
        "nonce": format!("0x{}", hex::encode(header.nonce().unwrap_or_default().0)),
        "transactions": tx_array,
        "uncles": Value::Array(vec![]),
    });

    let m = block.as_object_mut().unwrap();
    if let Some(v) = header.base_fee_per_gas() { m.insert("baseFeePerGas".into(), json!(u64_hex(v))); }
    if let Some(v) = header.withdrawals_root() { m.insert("withdrawalsRoot".into(), json!(hex(&v.0))); }
    if let Some(v) = header.blob_gas_used() { m.insert("blobGasUsed".into(), json!(u64_hex(v))); }
    if let Some(v) = header.excess_blob_gas() { m.insert("excessBlobGas".into(), json!(u64_hex(v))); }
    if let Some(v) = header.parent_beacon_block_root() { m.insert("parentBeaconBlockRoot".into(), json!(hex(&v.0))); }
    if let Some(v) = header.requests_hash() { m.insert("requestsHash".into(), json!(hex(&v.0))); }
    if let Some(wds) = rb.body().withdrawals.as_ref() {
        m.insert("withdrawals".into(), serde_json::to_value(wds).unwrap_or(json!([])));
    }

    block
}

fn eest_header_to_block_value(h: &EestHeader, txs: &[Value]) -> Value {
    let mut block = json!({
        "hash": hex(&h.hash.0),
        "parentHash": hex(&h.parent_hash.0),
        "sha3Uncles": hex(&h.uncle_hash.0),
        "miner": hex(&h.coinbase.0 .0),
        "stateRoot": hex(&h.state_root.0),
        "transactionsRoot": hex(&h.transactions_trie.0),
        "receiptsRoot": hex(&h.receipt_trie.0),
        "logsBloom": hex(h.bloom.0.as_slice()),
        "difficulty": u256_hex(&h.difficulty),
        "number": u64_hex(h.number.to::<u64>()),
        "gasLimit": u64_hex(h.gas_limit.to::<u64>()),
        "gasUsed": u64_hex(h.gas_used.to::<u64>()),
        "timestamp": u64_hex(h.timestamp.to::<u64>()),
        "extraData": format!("0x{}", hex::encode(&h.extra_data)),
        "mixHash": hex(&h.mix_hash.0),
        "nonce": format!("0x{}", hex::encode(h.nonce.0)),
        "transactions": txs,
        "uncles": Value::Array(vec![]),
    });
    let m = block.as_object_mut().unwrap();
    if let Some(v) = h.base_fee_per_gas { m.insert("baseFeePerGas".into(), json!(u64_hex(v.to::<u64>()))); }
    if let Some(v) = h.withdrawals_root { m.insert("withdrawalsRoot".into(), json!(hex(&v.0))); }
    if let Some(v) = h.blob_gas_used { m.insert("blobGasUsed".into(), json!(u64_hex(v.to::<u64>()))); }
    if let Some(v) = h.excess_blob_gas { m.insert("excessBlobGas".into(), json!(u64_hex(v.to::<u64>()))); }
    if let Some(v) = h.parent_beacon_block_root { m.insert("parentBeaconBlockRoot".into(), json!(hex(&v.0))); }
    if let Some(v) = h.requests_hash { m.insert("requestsHash".into(), json!(hex(&v.0))); }
    block
}

// ===== System-contract slots ===========================================

/// Mirror of `SYSTEM_CONTRACTS` + `slot_u64` in
/// `rust-input-gen/src/main.rs`.
fn system_contract_slots(number: u64, timestamp: u64) -> BTreeSet<(Address, B256)> {
    const RING: u64 = 8191;
    let beacon_root: Address = "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02".parse().unwrap();
    let hist_blk: Address = "0x0000F90827F1C53a10cb7A02335B175320002935".parse().unwrap();
    let wd_req: Address = "0x00000961Ef480Eb55e80D19ad83579A64c007002".parse().unwrap();
    let cons_req: Address = "0x0000BBdDc7CE488642fb579F8B00f3a590007251".parse().unwrap();

    let mut s = BTreeSet::new();
    let t1 = timestamp % RING;
    s.insert((beacon_root, slot_u64(t1)));
    s.insert((beacon_root, slot_u64(t1 + RING)));
    s.insert((hist_blk, slot_u64(number.saturating_sub(1) % RING)));
    for i in 0..4 {
        s.insert((wd_req, slot_u64(i)));
        s.insert((cons_req, slot_u64(i)));
    }
    s
}

fn slot_u64(v: u64) -> B256 {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    B256::from(b)
}

// ===== hex helpers =====================================================

fn hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn u64_hex(v: u64) -> String {
    format!("0x{:x}", v)
}

fn u256_hex(v: &U256) -> String {
    format!("0x{:x}", v)
}

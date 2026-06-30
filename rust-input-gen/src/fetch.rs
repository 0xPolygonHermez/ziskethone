//! Live-RPC fetching: all logic to build an `OfflineSources` bundle
//! from a JSON-RPC endpoint. Extracted from `main.rs` so the library
//! can expose in-process entry points without spawning the CLI.

use alloy::primitives::{Address, B256};
use anyhow::{Context, Result};
use tracing::info;

use crate::enrich;
use crate::mpt;
use crate::offline::OfflineSources;
use crate::rpc;

/// Live-RPC adapter: fetch everything `OfflineSources` needs from
/// the node, with all the reorg-safety guarantees (hash pinning,
/// parent-hash chain walk, end-of-run reverify). Returns a fully
/// resolved bundle that `offline::build_binary` can encode without
/// further network access.
pub(crate) async fn fetch_offline_sources_online(
    client: &rpc::Client,
    block: u64,
    ancestors_depth: u64,
) -> Result<OfflineSources> {
    // ---- (1) Discover the canonical anchor hash ----
    //
    // Single by-number call in the whole run. From this point on,
    // every subsequent RPC is pinned to `block_hash` or `parent_hash`,
    // so a mid-run reorg cannot silently corrupt our data — it shows
    // up either as an RPC error (hash no longer canonical & pruned)
    // or as the end-of-run reverify catching a hash drift.
    let current = client.block_by_number_full(block).await?;
    let block_hash: B256 = current.header.hash;
    let parent_hash: B256 = current.header.parent_hash;
    info!(
        %block_hash,
        %parent_hash,
        "anchored block hash",
    );

    // ---- Fetch the execution witness FIRST, before any other heavy RPC.
    //      `debug_executionWitness` reads the block's trie state, which a
    //      non-archive node prunes within a few blocks of head. Issuing it
    //      immediately — rather than after the 256-block ancestor walk and
    //      the prestate tracers — captures a COMPLETE witness while the
    //      node still has the data; otherwise it comes back missing
    //      intermediate nodes and the cpp-guest's strict state-root
    //      reconstruction rejects the block.
    let mut witness = client.execution_witness_by_hash(block_hash).await?;
    info!(
        state_nodes = witness.state.len(),
        codes = witness.codes.len(),
        keys = witness.keys.len(),
        "fetched execution witness",
    );

    // Resolve whether this block runs under Osaka. Osaka shares Prague's
    // header layout, so the only signal is the node's fork schedule
    // (eth_config) vs. the block timestamp. Best-effort: a node without
    // eth_config yields `None` → treated as pre-Osaka (Prague).
    let osaka_at = client.osaka_activation_time().await?;
    let is_osaka = matches!(osaka_at, Some(t) if current.header.timestamp >= t);
    if is_osaka {
        info!(
            timestamp = current.header.timestamp,
            osaka_activation = ?osaka_at,
            "block runs under Osaka",
        );
    }

    // Resolve this block's BLOB_BASE_FEE_UPDATE_FRACTION from the node's blob
    // schedule (eth_config). 0 ⇒ unresolved/pre-Cancun → the guest applies its
    // current-mainnet default. Threaded into ConsensusInfo so blob base fees
    // match the active schedule (mainnet BPO forks; EEST base-Osaka differs).
    let blob_base_fee_update_fraction = client
        .blob_base_fee_update_fraction_at(current.header.timestamp)
        .await?
        .unwrap_or(0);
    info!(
        blob_base_fee_update_fraction,
        "resolved blob base-fee update fraction"
    );

    {
        use alloy::rpc::types::BlockTransactions;
        if let BlockTransactions::Full(v) = &current.transactions {
            tracing::info!(txs = v.len(), "alloy parsed block.transactions");
        }
    }

    // ---- (2) Parent block by hash (must follow step 1; we need its
    //         hash). Header carries `parent.header.state_root` which
    //         anchors every MPT walk below.
    let parent = client.block_by_hash(parent_hash).await?;
    info!(parent_state_root = %parent.header.state_root, "fetched parent header");

    // ---- (3) Ancestor chain walked by parent-hash. This is
    //         intrinsically reorg-immune: each fetched header's hash
    //         must match the previous one's parent_hash by construction.
    let mut ancestors = vec![parent.clone()];
    let zero_hash = B256::ZERO;
    while (ancestors.len() as u64) < ancestors_depth {
        let prev = ancestors.last().unwrap();
        if prev.header.number == 0 {
            // Reached genesis; no further ancestors exist.
            break;
        }
        let next_hash = prev.header.parent_hash;
        if next_hash == zero_hash {
            // Defensive: should never happen for non-genesis headers,
            // but a malformed node response shouldn't loop forever.
            break;
        }
        let next = client.block_by_hash(next_hash).await?;
        ancestors.push(next);
    }
    info!(count = ancestors.len(), "fetched ancestor chain");

    // ---- (4) Phase 3: fetch all data sources in parallel, all
    //         pinned to `block_hash`.
    let (mut prestate, diff) = tokio::try_join!(
        client.prestate_by_hash(block_hash),
        client.prestate_diff_by_hash(block_hash),
    )?;
    info!(
        accounts = prestate.len(),
        storage_slots = prestate.values().map(|p| p.storage.len()).sum::<usize>(),
        "fetched prestate"
    );

    enrich::inject_tx_addresses(&mut prestate, &current);
    info!(
        accounts = prestate.len(),
        "injected tx-derived addresses (incl. EIP-7702 signers)"
    );

    let system_contract_slots =
        inject_system_contracts(client, &mut prestate, &current, block_hash, parent_hash).await?;
    info!(
        accounts = prestate.len(),
        "added Pectra system-contract entries"
    );

    inject_withdrawal_recipients(client, &mut prestate, &current, parent_hash).await?;
    info!(accounts = prestate.len(), "added withdrawal recipients");

    enrich::enrich_prestate_from_witness(
        client,
        parent.header.state_root,
        parent_hash,
        &witness,
        &mut prestate,
    )
    .await?;

    backfill_witness_gaps(
        client,
        parent.header.state_root,
        parent_hash,
        &prestate,
        &mut witness,
    )
    .await?;

    enrich::enrich_state_leaves_from_witness(
        client,
        parent.header.state_root,
        parent_hash,
        &witness,
        &mut prestate,
    )
    .await?;

    enrich::enrich_storage_slots_from_witness(parent.header.state_root, &witness, &mut prestate)?;

    // ---- (5) End-of-run reorg reverify ----
    {
        use crate::errors::ReorgDetected;
        let now = client.block_by_number_full(block).await?;
        if now.header.hash != block_hash || now.header.number != block {
            return Err(ReorgDetected {
                block,
                expected: block_hash,
                actual: Some(now.header.hash),
                phase: "end-of-run reverify",
            }
            .into());
        }
    }

    Ok(OfflineSources {
        current,
        parent,
        ancestors,
        prestate,
        diff,
        witness,
        system_contract_slots,
        is_osaka,
        blob_base_fee_update_fraction,
    })
}

/// Splice in account leaves that reth's `debug_executionWitness` omitted.
async fn backfill_witness_gaps(
    client: &rpc::Client,
    parent_state_root: B256,
    parent_hash: B256,
    prestate: &rpc::Prestate,
    witness: &mut rpc::ExecutionWitness,
) -> Result<()> {
    use std::collections::{HashMap, HashSet};

    let mut nodes: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(witness.state.len());
    for raw in &witness.state {
        if raw.len() >= 32 {
            nodes.insert(mpt::keccak256(raw), raw.to_vec());
        }
    }
    let root: [u8; 32] = parent_state_root.0;
    let mut have_key: HashSet<Vec<u8>> = witness.keys.iter().map(|k| k.to_vec()).collect();

    let mut missing: Vec<(Address, bool)> = Vec::new();
    for (addr, acct) in prestate.iter() {
        if have_key.contains(addr.as_slice()) {
            continue;
        }
        let non_empty = acct.balance.map(|b| !b.is_zero()).unwrap_or(false)
            || acct.nonce.map(|n| n != 0).unwrap_or(false)
            || acct.code.as_ref().map(|c| !c.is_empty()).unwrap_or(false);
        match mpt::lookup(&nodes, root, addr.as_slice())? {
            mpt::Lookup::Found(_) => missing.push((*addr, true)),
            mpt::Lookup::NotInWitness => missing.push((*addr, false)),
            mpt::Lookup::Absent => {
                if non_empty {
                    missing.push((*addr, false));
                }
            }
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    info!(count = missing.len(), "backfilling witness gaps");

    let mut have_node: HashSet<[u8; 32]> = nodes.keys().copied().collect();
    for (addr, leaf_present) in missing {
        if !leaf_present {
            let proof = client
                .account_proof_at_hash(addr, Vec::new(), parent_hash)
                .await?;
            for node in proof.account_proof {
                let h = mpt::keccak256(&node);
                if have_node.insert(h) {
                    witness.state.push(node);
                }
            }
        }
        let kb = addr.as_slice().to_vec();
        if have_key.insert(kb.clone()) {
            witness.keys.push(kb.into());
        }
    }
    Ok(())
}

struct SystemContract {
    addr: &'static str,
    slots: fn(current_number: u64, current_timestamp: u64) -> Vec<alloy::primitives::B256>,
}

const SYSTEM_CONTRACTS: &[SystemContract] = &[
    // EIP-4788 beacon roots: 2 slots per block.
    SystemContract {
        addr: "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02",
        slots: |_n, t| {
            const RING: u64 = 8191;
            let s1 = t % RING;
            let s2 = s1 + RING;
            vec![slot_u64(s1), slot_u64(s2)]
        },
    },
    // EIP-2935 block hashes: 1 slot for the parent's hash.
    SystemContract {
        addr: "0x0000F90827F1C53a10cb7A02335B175320002935",
        slots: |n, _t| {
            const RING: u64 = 8191;
            vec![slot_u64(n.saturating_sub(1) % RING)]
        },
    },
    // EIP-7002 withdrawal requests: queue counters live in low slots.
    SystemContract {
        addr: "0x00000961Ef480Eb55e80D19ad83579A64c007002",
        slots: |_n, _t| (0..4).map(slot_u64).collect(),
    },
    // EIP-7251 consolidation requests: same shape as 7002.
    SystemContract {
        addr: "0x0000BBdDc7CE488642fb579F8B00f3a590007251",
        slots: |_n, _t| (0..4).map(slot_u64).collect(),
    },
];

fn slot_u64(v: u64) -> alloy::primitives::B256 {
    let mut s = [0u8; 32];
    s[24..].copy_from_slice(&v.to_be_bytes());
    alloy::primitives::B256::from(s)
}

async fn inject_withdrawal_recipients(
    client: &rpc::Client,
    prestate: &mut rpc::Prestate,
    current: &alloy::rpc::types::Block,
    parent_hash: B256,
) -> Result<()> {
    use alloy::primitives::Address;

    let mut uniq: std::collections::BTreeSet<Address> = Default::default();
    if let Some(wds) = &current.withdrawals {
        for wd in wds.iter() {
            uniq.insert(wd.address);
        }
    }

    for addr in uniq {
        let entry = prestate.entry(addr).or_default();
        if entry.balance.is_none() {
            entry.balance = Some(client.balance_at_hash(addr, parent_hash).await?);
        }
        if entry.nonce.is_none() {
            entry.nonce = Some(client.nonce_at_hash(addr, parent_hash).await?);
        }
    }
    Ok(())
}

async fn inject_system_contracts(
    client: &rpc::Client,
    prestate: &mut rpc::Prestate,
    current: &alloy::rpc::types::Block,
    block_hash: B256,
    parent_hash: B256,
) -> Result<std::collections::BTreeSet<(alloy::primitives::Address, alloy::primitives::B256)>> {
    use alloy::primitives::Address;

    let number = current.header.number;
    let timestamp = current.header.timestamp;

    let mut writable: std::collections::BTreeSet<(Address, alloy::primitives::B256)> =
        Default::default();

    for sc in SYSTEM_CONTRACTS {
        let addr: Address = sc.addr.parse().context("bad SYSTEM_CONTRACTS addr")?;
        let entry = prestate.entry(addr).or_default();

        if entry.code.is_none() {
            entry.code = Some(client.code_at_hash(addr, block_hash).await?);
        }
        if entry.balance.is_none() {
            entry.balance = Some(client.balance_at_hash(addr, parent_hash).await?);
        }
        if entry.nonce.is_none() {
            entry.nonce = Some(client.nonce_at_hash(addr, parent_hash).await?);
        }

        for slot in (sc.slots)(number, timestamp) {
            writable.insert((addr, slot));
            let v = client.storage_at_hash(addr, slot, parent_hash).await?;
            entry.storage.insert(slot, v);
        }
    }
    Ok(writable)
}

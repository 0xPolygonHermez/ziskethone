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

    // Fetch `eth_config` once; both the Osaka check and the blob-schedule
    // lookup below derive from it.
    let eth_config = client.eth_config().await;

    // Resolve whether this block runs under Osaka. Osaka shares Prague's
    // header layout, so the only signal is the node's fork schedule
    // (eth_config) vs. the block timestamp. Best-effort: a node without
    // eth_config yields `None` → treated as pre-Osaka (Prague).
    let osaka_at = rpc::Client::osaka_activation_time(eth_config.as_ref());
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
    let blob_base_fee_update_fraction = rpc::Client::blob_base_fee_update_fraction_at(
        eth_config.as_ref(),
        current.header.timestamp,
    )
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

    // ---- (3) Ancestor chain: `ancestors[0]` is the parent, `ancestors[i]`
    //         is block parent.number - i. Fetched concurrently by number.
    let ancestors = fetch_ancestor_chain(client, &parent, ancestors_depth).await?;
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

/// Max ancestor requests in flight at once — caps load on the node.
const ANCESTOR_FETCH_CONCURRENCY: usize = 32;

/// Fetch `[parent, grandparent, …]` (index `i` = block `parent.number - i`),
/// fetching the ancestors concurrently by number.
///
/// Reorg-safety: fetching by number could resolve to an off-canonical
/// block if the node reorgs mid-run, so we then assert the parent-hash
/// linkage in memory — `child.parent_hash == ancestor.hash` at every
/// step. A mismatch is a reorg, surfaced as `ReorgDetected` for retry.
async fn fetch_ancestor_chain(
    client: &rpc::Client,
    parent: &alloy::rpc::types::Block,
    ancestors_depth: u64,
) -> Result<Vec<alloy::rpc::types::Block>> {
    use crate::errors::ReorgDetected;
    use futures::stream::{self, StreamExt, TryStreamExt};

    // Ancestor numbers, from parent-1 down, clamped at genesis (block 0).
    let parent_number = parent.header.number;
    let want = ancestors_depth.saturating_sub(1).min(parent_number);
    if want == 0 {
        return Ok(vec![parent.clone()]);
    }
    let numbers: Vec<u64> = (1..=want).map(|i| parent_number - i).collect();

    // `buffered` preserves input order, so `fetched[j]` is `numbers[j]`.
    let fetched: Vec<alloy::rpc::types::Block> = stream::iter(numbers.iter().copied())
        .map(|n| async move {
            client.block_by_number(n).await?.ok_or_else(|| {
                // Empty for a number that should exist ⇒ pruned/reorged out.
                anyhow::Error::new(ReorgDetected {
                    block: n,
                    expected: B256::ZERO,
                    actual: None,
                    phase: "ancestor eth_getBlockByNumber (Ok(None))",
                })
            })
        })
        .buffered(ANCESTOR_FETCH_CONCURRENCY)
        .try_collect()
        .await?;

    // Verify each block links to the next (see reorg-safety note above).
    let mut ancestors = Vec::with_capacity(fetched.len() + 1);
    ancestors.push(parent.clone());
    for next in fetched {
        let prev = ancestors.last().unwrap();
        if prev.header.parent_hash != next.header.hash {
            return Err(ReorgDetected {
                block: next.header.number,
                expected: prev.header.parent_hash,
                actual: Some(next.header.hash),
                phase: "ancestor chain linkage",
            }
            .into());
        }
        ancestors.push(next);
    }
    Ok(ancestors)
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

    // Fetch each recipient's missing balance/nonce concurrently, then apply.
    let needs: Vec<(Address, bool, bool)> = uniq
        .into_iter()
        .map(|addr| {
            let e = prestate.entry(addr).or_default();
            (addr, e.balance.is_none(), e.nonce.is_none())
        })
        .collect();

    let fetched = futures::future::try_join_all(needs.iter().map(
        |&(addr, need_bal, need_nonce)| async move {
            let balance = if need_bal {
                Some(client.balance_at_hash(addr, parent_hash).await?)
            } else {
                None
            };
            let nonce = if need_nonce {
                Some(client.nonce_at_hash(addr, parent_hash).await?)
            } else {
                None
            };
            anyhow::Ok((addr, balance, nonce))
        },
    ))
    .await?;

    for (addr, balance, nonce) in fetched {
        let entry = prestate.entry(addr).or_default();
        if let Some(b) = balance {
            entry.balance = Some(b);
        }
        if let Some(n) = nonce {
            entry.nonce = Some(n);
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

    // Plan each contract's needed fields + writable slots (no RPC), then
    // fetch code/balance/nonce/storage for all four contracts concurrently.
    struct Plan {
        addr: Address,
        need_code: bool,
        need_balance: bool,
        need_nonce: bool,
        slots: Vec<alloy::primitives::B256>,
    }
    let mut plans = Vec::with_capacity(SYSTEM_CONTRACTS.len());
    for sc in SYSTEM_CONTRACTS {
        let addr: Address = sc.addr.parse().context("bad SYSTEM_CONTRACTS addr")?;
        let entry = prestate.entry(addr).or_default();
        let slots = (sc.slots)(number, timestamp);
        for slot in &slots {
            writable.insert((addr, *slot));
        }
        plans.push(Plan {
            addr,
            need_code: entry.code.is_none(),
            need_balance: entry.balance.is_none(),
            need_nonce: entry.nonce.is_none(),
            slots,
        });
    }

    let fetched = futures::future::try_join_all(plans.iter().map(|p| async move {
        let code = if p.need_code {
            Some(client.code_at_hash(p.addr, block_hash).await?)
        } else {
            None
        };
        let balance = if p.need_balance {
            Some(client.balance_at_hash(p.addr, parent_hash).await?)
        } else {
            None
        };
        let nonce = if p.need_nonce {
            Some(client.nonce_at_hash(p.addr, parent_hash).await?)
        } else {
            None
        };
        let storage = futures::future::try_join_all(p.slots.iter().map(|&slot| async move {
            let v = client.storage_at_hash(p.addr, slot, parent_hash).await?;
            anyhow::Ok((slot, v))
        }))
        .await?;
        anyhow::Ok((p.addr, code, balance, nonce, storage))
    }))
    .await?;

    for (addr, code, balance, nonce, storage) in fetched {
        let entry = prestate.entry(addr).or_default();
        if let Some(c) = code {
            entry.code = Some(c);
        }
        if let Some(b) = balance {
            entry.balance = Some(b);
        }
        if let Some(n) = nonce {
            entry.nonce = Some(n);
        }
        for (slot, v) in storage {
            entry.storage.insert(slot, v);
        }
    }
    Ok(writable)
}

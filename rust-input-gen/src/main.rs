//! `input-gen` — fetch one Ethereum block's stateless-re-execution
//! inputs from a JSON-RPC endpoint and write a binary file the ZisK
//! C++ guest (`zisk_eth_guest`) consumes. See `BINARY_FORMAT.md`.
//!
//! Phase 4: every input-stream section is real (ConsensusInfo,
//! Transactions, Accounts, Contracts, Storages, PreviousBlocks).
//! StateRoot trie-hint stream remains a single `Op::Empty` placeholder
//! until Phase 5.

use std::path::PathBuf;

use alloy::primitives::B256;
use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

mod enrich;
mod errors;
mod mpt;
mod rpc;
mod sections;
mod state_root;
mod touchset;
mod verify;
mod writer;

use errors::ReorgDetected;
use touchset::TouchSet;
use writer::Writer;

/// sysexits.h `EX_TEMPFAIL` — returned to the OS when we detect that
/// the upstream node reorged during our run. `scripts/verify_blocks.py`
/// recognizes this code and re-queues the block instead of recording
/// a failure. Any other error keeps the existing non-zero exit (1).
const EXIT_CODE_REORG: i32 = 75;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// JSON-RPC endpoint URL. The node must support the standard
    /// `eth_*` namespace; later phases also need `debug_*`.
    #[arg(long, env = "ETH_RPC_URL", default_value = "http://localhost:8545")]
    rpc_url: String,

    /// Block number to fetch.
    #[arg(long)]
    block: u64,

    /// Number of ancestor blocks to include in the PreviousBlocks
    /// section. Index 0 = parent (always included — the cpp-guest
    /// derives parent's block hash from this entry for BLOCKHASH and
    /// for the reconstructed header). Index 1 = grandparent, ....
    /// The EVM BLOCKHASH opcode reaches back 256, so the default is
    /// 256 (the spec-maximum) — any value lower risks an in-block
    /// BLOCKHASH(N) returning zeros and diverging execution.
    #[arg(long, default_value_t = 256)]
    ancestors: u64,

    /// Output binary path.
    #[arg(long, default_value = "build/block_input.bin")]
    output: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if let Err(err) = run(args).await {
        // Distinguish reorg-class errors (transient, retryable) from
        // every other failure so `scripts/verify_blocks.py` can
        // auto-retry without recording a failure artifact.
        if let Some(reorg) = err.downcast_ref::<ReorgDetected>() {
            eprintln!("Error: {reorg}");
            std::process::exit(EXIT_CODE_REORG);
        }
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<()> {
    info!(
        block = args.block,
        rpc = %args.rpc_url,
        output = %args.output.display(),
        ancestors = args.ancestors,
        "fetching block bundle",
    );

    let client = rpc::Client::new(&args.rpc_url)?;

    if args.block == 0 {
        anyhow::bail!("block 0 has no parent; pick a later block");
    }

    // ---- (1) Discover the canonical anchor hash ----
    //
    // Single by-number call in the whole run. From this point on,
    // every subsequent RPC is pinned to `block_hash` or `parent_hash`,
    // so a mid-run reorg cannot silently corrupt our data — it shows
    // up either as an RPC error (hash no longer canonical & pruned)
    // or as the end-of-run reverify catching a hash drift.
    let current = client.block_by_number_full(args.block).await?;
    let block_hash: B256 = current.header.hash;
    let parent_hash: B256 = current.header.parent_hash;
    info!(
        %block_hash,
        %parent_hash,
        "anchored block hash",
    );

    {
        use alloy::rpc::types::BlockTransactions;
        if let BlockTransactions::Full(v) = &current.transactions {
            tracing::info!(txs = v.len(), "alloy parsed block.transactions");
            for (i, t) in v.iter().enumerate().take(5) {
                println!("alloy tx[{i}] hash={} from={}", t.inner.tx_hash(), t.from);
            }
            if let Some(last) = v.last() {
                println!("... last alloy tx hash={}", last.inner.tx_hash());
            }
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
    while (ancestors.len() as u64) < args.ancestors {
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
    //         pinned to `block_hash`. See the original commentary
    //         below for what each source provides.
    //
    //   * `prestateTracer` (non-diff) — every account + slot the EVM
    //     READ or WROTE during execution, with their block-start
    //     values. The authoritative source for "what does the EVM
    //     access", including SLOADs of zero-value slots that have no
    //     leaf in the parent state trie.
    //
    //   * `prestateTracer` (diff mode) — only the fields that changed
    //     during the block. Drives the `is_read_only` flag in the
    //     binary's Accounts / Storages records.
    //
    //   * `debug_executionWitnessByHash` — every MPT node touched
    //     during execution (state + storage tries), the deployed code
    //     blobs, and the keccak preimages for keys. Used both as the
    //     canonical source for parent-state values AND to discover
    //     leaves the prestate tracer omits (notably: untouched-
    //     sibling leaves that the cpp-guest's state-root walker
    //     needs to reposition during structural splits).
    let (mut prestate, diff, witness) = tokio::try_join!(
        client.prestate_by_hash(block_hash),
        client.prestate_diff_by_hash(block_hash),
        client.execution_witness_by_hash(block_hash),
    )?;
    info!(
        accounts = prestate.len(),
        storage_slots = prestate.values().map(|p| p.storage.len()).sum::<usize>(),
        "fetched prestate"
    );
    info!(
        state_nodes = witness.state.len(),
        codes = witness.codes.len(),
        keys = witness.keys.len(),
        "fetched execution witness",
    );

    // Inject the four Pectra system contracts (EIP-4788 / 2935 / 7002
    // / 7251). The cpp-guest's `pre_execute_block` / `post_execute_block`
    // CALL these from `0xfffe`; the prestate tracer captures tx
    // execution only and misses pre/post-block system calls, so these
    // addresses aren't in the trace. Fetch their bytecode + the
    // touched ring-buffer slots explicitly via RPC, all hash-pinned.
    let system_contract_slots = inject_system_contracts(
        &client,
        &mut prestate,
        &current,
        block_hash,
        parent_hash,
    )
    .await?;
    info!(
        accounts = prestate.len(),
        "added Pectra system-contract entries"
    );

    // Withdrawal recipients (EIP-4895) — credited at block boundary
    // outside any tx, so the prestate tracer never sees them.
    inject_withdrawal_recipients(&client, &mut prestate, &current, parent_hash).await?;
    info!(
        accounts = prestate.len(),
        "added withdrawal recipients"
    );

    // Patch existing prestate entries with canonical values from the
    // parent state trie (the tracer omits unread fields).
    enrich::enrich_prestate_from_witness(
        &client,
        parent.header.state_root,
        parent_hash,
        &witness,
        &mut prestate,
    ).await?;

    // Walk the parent state trie and append every account leaf the
    // witness exposes (notably: off-target sibling leaves that the
    // tracer misses). After this step every state-trie leaf reachable
    // in the witness exists in `prestate`, so the state-root walker
    // can reference it via `Op::Leaf <idx>` and never needs the
    // legacy `Op::PhantomLeaf` carry-bytes trick.
    enrich::enrich_state_leaves_from_witness(
        &client,
        parent.header.state_root,
        parent_hash,
        &witness,
        &mut prestate,
    ).await?;

    // Walk every touched account's parent storage trie and append any
    // leaf the prestate tracer missed (notably: slots whose only
    // access lived inside a reverted frame). After this step every
    // leaf reachable in the witness exists in `prestate`, so the
    // state-root walker can reference it via `Op::Leaf <idx>` and
    // never needs the legacy `Op::PhantomLeaf` carry-bytes trick.
    enrich::enrich_storage_slots_from_witness(
        parent.header.state_root,
        &witness,
        &mut prestate,
    )?;

    // Single source of ordering for Accounts / Storages / StateRoot.
    let touch = TouchSet::build(&prestate, &diff);
    info!(
        accounts = touch.addrs.len(),
        slots = touch.slots.len(),
        "built TouchSet",
    );

    // Verifier: walk the parent state trie from the witness and
    // compare every touched account/slot value against what we'd
    // write. Prints `state account VALUE mismatch` / `storage VALUE
    // mismatch` for each discrepancy — pin-points which entry breaks
    // the cpp-guest's `old_state_root` recomputation.
    verify::check(
        parent.header.state_root,
        &witness,
        &prestate,
        &diff,
        &touch,
    )?;

    // ---- (5) End-of-run reorg reverify ----
    //
    // Belt-and-suspenders. Even though every fetch above was pinned
    // to a hash, a node that pruned the side chain mid-run may have
    // returned partial data for one of the hash-pinned calls. This
    // final by-number lookup confirms the canonical chain still
    // resolves `args.block` to our anchored `block_hash`. Run it
    // BEFORE writing the file so a reorg never produces a corrupt
    // artifact.
    {
        let now = client.block_by_number_full(args.block).await?;
        if now.header.hash != block_hash || now.header.number != args.block {
            return Err(ReorgDetected {
                block: args.block,
                expected: block_hash,
                actual: Some(now.header.hash),
                phase: "end-of-run reverify",
            }
            .into());
        }
    }

    // Encode.
    let mut w = Writer::new();
    sections::write_magic(&mut w);
    sections::write_consensus_info(&mut w, &current, &parent);
    sections::write_transactions(&mut w, &current)?;
    sections::write_accounts(&mut w, &prestate, &diff, &touch, &current)?;
    sections::write_contracts(&mut w, &prestate, &diff, &current)?;
    sections::write_storages(&mut w, &prestate, &diff, &touch, &system_contract_slots)?;
    sections::write_previous_blocks(&mut w, &ancestors);
    state_root::write(
        &mut w,
        parent.header.state_root,
        &witness.state,
        &touch,
        &diff,
    )?;

    let bytes = w.into_bytes();
    if let Some(parent_dir) = args.output.parent() {
        std::fs::create_dir_all(parent_dir)
            .with_context(|| format!("creating output dir {}", parent_dir.display()))?;
    }
    std::fs::write(&args.output, &bytes)
        .with_context(|| format!("writing {}", args.output.display()))?;

    info!(path = %args.output.display(), bytes = bytes.len(), "wrote input file");
    Ok(())
}

/// Pectra system contracts the cpp-guest's `pre_execute_block` /
/// `post_execute_block` invoke. The prestate tracer misses these
/// because it only covers tx execution; we inject minimal entries so
/// `index_of` finds them at runtime.
struct SystemContract {
    addr: &'static str,
    /// Slot indices this system call touches in this block. The
    /// cpp-guest requires every (addr, slot) used by SLOAD/SSTORE to
    /// be pre-registered in the Storages table; for EIP-4788/2935
    /// the ring-buffer slot is deterministic; for EIP-7002/7251 the
    /// queue head/tail counters are at slots 0..4 (over-registering
    /// is harmless).
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
            // Writes (n - 1) % RING — the parent block's slot.
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

/// Inject EOA entries for every withdrawal recipient in `current`.
/// Withdrawals (EIP-4895) credit balances outside any tx, so the
/// prestate tracer never includes them — but the cpp-guest's
/// `process_withdrawals` calls `accounts_.index_of(recipient)` and
/// would fatal otherwise. Pre-block values (balance + nonce) come
/// from the parent block hash via `eth_getBalance` / `eth_getTransactionCount`.
async fn inject_withdrawal_recipients(
    client: &rpc::Client,
    prestate: &mut rpc::Prestate,
    current: &alloy::rpc::types::Block,
    parent_hash: B256,
) -> Result<()> {
    use alloy::primitives::Address;

    // Unique recipients only — most blocks have repeats from the same
    // validator's multiple withdrawals.
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

    let number    = current.header.number;
    let timestamp = current.header.timestamp;

    let mut writable: std::collections::BTreeSet<(Address, alloy::primitives::B256)> =
        Default::default();

    for sc in SYSTEM_CONTRACTS {
        let addr: Address = sc.addr.parse().context("bad SYSTEM_CONTRACTS addr")?;
        let entry = prestate.entry(addr).or_default();

        if entry.code.is_none() {
            // Code is the same at any block once the EIP went live;
            // fetch at the current block hash (no historical-state
            // requirement under the node's pruning).
            entry.code = Some(client.code_at_hash(addr, block_hash).await?);
        }
        // Balance must come from chain — EIP-7002 (withdrawal-requests)
        // and EIP-7251 (consolidation-requests) accumulate per-request
        // fees, so the system contract's balance is non-zero on a live
        // chain. The block-start balance is the value at the parent.
        if entry.balance.is_none() {
            entry.balance = Some(client.balance_at_hash(addr, parent_hash).await?);
        }
        if entry.nonce.is_none() {
            entry.nonce = Some(client.nonce_at_hash(addr, parent_hash).await?);
        }

        for slot in (sc.slots)(number, timestamp) {
            // Every injected slot is touched by the pre/post-block
            // system call — record it so write_storages marks it
            // writable (the prestate diff never sees these because
            // system calls aren't transactions).
            writable.insert((addr, slot));
            // ALWAYS overwrite with the parent-block value. The
            // prestateTracer reports per-tx state at tx start, but
            // the pre-block EIP-4788/2935/7002/7251 system calls
            // run BEFORE any tx — so any tx that reads these slots
            // sees the POST-system-call value, and our aggregated
            // prestate would record that as "block-start", which is
            // wrong. The true block-start value is at parent-block
            // (= before this block's system call writes the new
            // ring-buffer entry).
            let v = client.storage_at_hash(addr, slot, parent_hash).await?;
            entry.storage.insert(slot, v);
        }
    }
    Ok(writable)
}

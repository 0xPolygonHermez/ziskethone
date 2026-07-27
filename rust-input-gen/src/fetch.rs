//! Live-RPC fetching: all logic to build an `OfflineSources` bundle
//! from a JSON-RPC endpoint. Extracted from `main.rs` so the library
//! can expose in-process entry points without spawning the CLI.

use alloy::primitives::B256;
use anyhow::Result;
use tracing::info;

use crate::offline::OfflineSources;
use crate::rpc;

/// Live-RPC adapter: fetch everything `OfflineSources` needs from
/// the node, with all the reorg-safety guarantees (hash pinning, the
/// witness's own post-fetch canonical recheck). Ancestors come solely
/// from `witness.headers` — no RPC ancestor walk. Returns a fully
/// resolved bundle that `offline::build_binary` can encode without
/// further network access.
pub(crate) async fn fetch_offline_sources_online(
    client: &rpc::Client,
    block: u64,
    // Retained for API/CLI compatibility. Ancestors now come solely from
    // `witness.headers` (the guest resolves BLOCKHASH by number over a
    // sparse set), so there is no RPC ancestor walk left to depth-bound.
    _ancestors_depth: u64,
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

    // Witness first (a non-archive node prunes trie state within a few blocks
    // of head, so grab it before anything else). Sequential — no concurrency.
    let witness = client.execution_witness_by_hash(block_hash).await?;
    info!(
        state_nodes = witness.state.len(),
        codes = witness.codes.len(),
        keys = witness.keys.len(),
        headers = witness.headers.len(),
        "fetched execution witness",
    );

    // Parent header comes from the WITNESS, not a separate RPC: reth's witness
    // carries every ancestor header the block touched (parent + deeper
    // BLOCKHASH targets) in `witness.headers`, and its state trie root IS the
    // pre-state root. Recovering the parent here (the header whose hash equals
    // the anchored `current.parent_hash`) removes an RPC call and matches
    // reth's own witness-only stateless-validator input shape.
    let parent = parent_from_witness(&witness, parent_hash)?;
    info!(parent_state_root = %parent.header.state_root, "recovered parent header from witness");

    // Fork schedule is COMPILED IN (mainnet), not fetched — reth's client does
    // the same (baked chain config selected by chain id), so we drop the
    // per-block `eth_config` RPC. This online path is mainnet-replay only (EEST
    // uses the manifest path, which carries its own fork_id/blob fraction), so
    // the mainnet constants below are authoritative. `is_osaka` and the blob
    // BASE_FEE_UPDATE_FRACTION are resolved from the block timestamp against
    // that schedule. NB: update `mainnet_fork_params` at each mainnet fork/BPO.
    let (
        is_osaka,
        blob_base_fee_update_fraction,
        target_blob_gas_per_block,
        max_blob_gas_per_block,
    ) = mainnet_fork_params(current.header.timestamp);
    if is_osaka {
        info!(
            timestamp = current.header.timestamp,
            "block runs under Osaka"
        );
    }
    info!(
        blob_base_fee_update_fraction,
        "resolved blob base-fee update fraction (compiled-in mainnet schedule)"
    );

    {
        use alloy::rpc::types::BlockTransactions;
        if let BlockTransactions::Full(v) = &current.transactions {
            tracing::info!(txs = v.len(), "alloy parsed block.transactions");
        }
    }

    // BLOCK + WITNESS ONLY — no prestate tracer, no enrich, no backfill.
    //
    // The guest is now hash-keyed (v7): its Accounts/Storages tables are built
    // solely from the execution witness by `state_root::write` (keyed by the
    // trie path = keccak(addr)/keccak(slot)), and it reconstructs every key
    // hash from the leaf's own path nibbles — so it needs NO key preimage.
    // That removes the entire reason the prestate tracer + `witness.keys`
    // preimage-backfill existed. Contracts come from `witness.codes`,
    // ancestors from `witness.headers`. This is the reth-parity path: the
    // only per-block RPCs are the block, the witness, and eth_config, issued
    // sequentially (parent + all ancestors come from the witness, no RPC).
    //
    // `prestate`/`diff`/`system_contract_slots` are retained as empty in
    // `OfflineSources` for wire/manifest compatibility; nothing in the encode
    // path consumes them any more (the StateRoot + Contracts sections are
    // witness-only).
    let prestate = rpc::Prestate::default();
    let diff = rpc::PrestateDiff::default();
    let system_contract_slots = std::collections::BTreeSet::new();

    // PreviousBlocks: ancestor headers from `witness.headers` (reth includes
    // every header the block's execution touched — parent + any deeper
    // BLOCKHASH targets), exactly as reth's stateless validator consumes.
    // Witness-only, no RPC fallback: the guest now resolves BLOCKHASH by
    // block number over a SPARSE ancestor set, so whatever headers the
    // witness carries are sufficient. If `witness.headers` is empty (the
    // block did no BLOCKHASH), the set is just the parent (index 0).
    let ancestors = build_ancestors_from_witness(&witness, &parent);
    info!(
        count = ancestors.len(),
        "built ancestor set (block+witness only)"
    );

    // No separate end-of-run reorg reverify: with the block+witness-only
    // path, the only RPC after the anchor is `execution_witness_by_hash`,
    // which ALREADY re-confirms (step c) that the canonical block at
    // `number` still hashes to `block_hash` after fetching the witness —
    // covering the full reorg window. Nothing but a no-RPC ancestor build
    // happens afterward, so a second `block_by_number_full` here would be
    // redundant (it duplicated the witness call's recheck) and only added a
    // round-trip. The anchor pin + the witness recheck are the guarantees.

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
        target_blob_gas_per_block,
        max_blob_gas_per_block,
    })
}

/// Compiled-in MAINNET fork schedule — returns `(is_osaka, blob
/// BASE_FEE_UPDATE_FRACTION, TARGET_BLOB_GAS_PER_BLOCK, MAX_BLOB_GAS_PER_BLOCK)`
/// for a block at `timestamp`. Mirrors reth's baked chain config: the online
/// replay path is mainnet-only, so we don't fetch `eth_config`. Entries are
/// (fork activation unix time, base_fee_update_fraction, target_blob_count,
/// max_blob_count), newest first; pick the newest whose activation <= timestamp.
///
/// UPDATE THIS at each mainnet fork / blob-schedule (BPO) change.
/// - BPO2   : 2026-01-07 (activationTime 1767747671), fraction 11684671, target 14, max 21
/// - BPO1   : 2025-12-09 (1765290071),                fraction 8346193,  target 10, max 15
/// - Prague : 2025-05-07 (1746612311),                fraction 5007716,  target 6,  max 9
/// - Cancun : 2024-03-13 (1710338135),                fraction 3338477,  target 3,  max 6
///
/// `is_osaka` (EVM-revision dispatch) is tracked separately from the blob
/// schedule rows above — Osaka/Fusaka itself doesn't change the blob
/// target/fraction (only the later BPO forks do); it's approximated here to
/// BPO2's activation for simplicity, which is immaterial in practice since
/// this path only ever replays blocks within the node's ~32-block recent
/// window (see CLAUDE.md), long past both Osaka's and BPO1's activation.
fn mainnet_fork_params(timestamp: u64) -> (bool, u64, u64, u64) {
    const OSAKA_ACTIVATION: u64 = 1767747671;
    const GAS_PER_BLOB: u64 = 131_072;
    // (activation_time, base_fee_update_fraction, target_blob_count, max_blob_count), newest first.
    const SCHEDULE: &[(u64, u64, u64, u64)] = &[
        (1767747671, 11684671, 14, 21), // BPO2
        (1765290071, 8346193, 10, 15),  // BPO1
        (1746612311, 5007716, 6, 9),    // Prague
        (1710338135, 3338477, 3, 6),    // Cancun
    ];
    let is_osaka = timestamp >= OSAKA_ACTIVATION;
    let (fraction, target_blobs, max_blobs) = SCHEDULE
        .iter()
        .find(|(act, _, _, _)| timestamp >= *act)
        .map(|(_, f, t, m)| (*f, *t, *m))
        .unwrap_or((0, 0, 0)); // pre-Cancun: no blob schedule → guest default
    (
        is_osaka,
        fraction,
        target_blobs * GAS_PER_BLOB,
        max_blobs * GAS_PER_BLOB,
    )
}

/// Recover the parent `Block` from `witness.headers` — the RLP header whose
/// keccak hash equals `parent_hash` (from the trusted, anchored `current`
/// block, so it pins exactly which header is accepted). reth's witness always
/// carries the parent (the block reads its parent hash), and the header's
/// `state_root` is the pre-state root anchor. No RPC, no fallback: a witness
/// that omits the parent is a hard input-completeness error (matching reth,
/// whose stateless validator is a pure function of the witness).
fn parent_from_witness(
    witness: &rpc::ExecutionWitness,
    parent_hash: B256,
) -> Result<alloy::rpc::types::Block> {
    use alloy::consensus::Header;
    use alloy::rlp::Decodable;
    use alloy::rpc::types::{Block, Header as RpcHeader};

    for raw in &witness.headers {
        let mut slice: &[u8] = raw.as_ref();
        if let Ok(h) = Header::decode(&mut slice) {
            if h.hash_slow() == parent_hash {
                return Ok(Block {
                    header: RpcHeader::new(h),
                    ..Default::default()
                });
            }
        }
    }
    anyhow::bail!(
        "parent header {parent_hash} not in witness.headers ({} headers present)",
        witness.headers.len()
    );
}

/// Build the `PreviousBlocks` ancestor list from `witness.headers` — the
/// RLP-encoded ancestor headers reth's execution touched. No RPC. Returns
/// the list parent-first (index 0 = parent), descending by number.
///
/// SPARSE-OK. `witness.headers` contains only the ancestors the block
/// actually referenced for BLOCKHASH — which may be sparse (a tx doing
/// BLOCKHASH(N-1) and BLOCKHASH(N-100) yields just those two). The cpp-guest
/// now resolves BLOCKHASH BY BLOCK NUMBER over this set (not positionally),
/// so gaps are fine: any depth the block never asks for is simply absent and
/// the guest returns zero for it (never queried). We therefore emit whatever
/// the witness carries, without a contiguity requirement.
///
/// Index 0 is always the already-fetched parent `Block` (it carries the
/// anchor the guest checks against `ConsensusInfo::parent_hash`). If
/// `witness.headers` is empty (the block did no BLOCKHASH), the result is the
/// single-element `[parent]` list. Any header that fails to RLP-decode is
/// skipped; the parent (from RPC) is always index 0 regardless.
fn build_ancestors_from_witness(
    witness: &rpc::ExecutionWitness,
    parent: &alloy::rpc::types::Block,
) -> Vec<alloy::rpc::types::Block> {
    use alloy::consensus::Header;
    use alloy::rlp::Decodable;
    use alloy::rpc::types::{Block, Header as RpcHeader};

    let parent_number = parent.header.number;

    // Decode every RLP header the witness carries. A header that fails to
    // decode is skipped (the guest re-hashes and re-links every record it
    // does receive, so a dropped one at worst yields a BLOCKHASH-zero the
    // block wouldn't have referenced).
    let mut headers: Vec<Header> = Vec::with_capacity(witness.headers.len());
    for raw in &witness.headers {
        let mut slice: &[u8] = raw.as_ref();
        if let Ok(h) = Header::decode(&mut slice) {
            headers.push(h);
        }
    }

    // Order parent-first: descending block number, de-duplicated.
    headers.sort_by_key(|h| std::cmp::Reverse(h.number));
    headers.dedup_by_key(|h| h.number);

    // Index 0 must be the parent (the anchor). Emit it from the exact parent
    // Block we already fetched, then append every OTHER witness header
    // (dropping any duplicate of the parent's number — the parent Block is
    // authoritative for that slot).
    let mut out: Vec<Block> = Vec::with_capacity(headers.len() + 1);
    out.push(parent.clone());
    for h in headers.into_iter() {
        if h.number == parent_number {
            continue;
        }
        // Wrap the consensus header in an rpc Block (empty txs — the section
        // writer only reads header fields).
        out.push(Block {
            header: RpcHeader::new(h),
            ..Default::default()
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::consensus::Header;
    use alloy::primitives::B256;
    use alloy::rlp::Encodable;
    use alloy::rpc::types::{Block, Header as RpcHeader};

    /// Build a chain of `n` headers, index 0 = highest number (`top`), each
    /// linked to the next by `parent_hash`. Returns the headers (parent-first)
    /// and their RLP encodings.
    fn chain(top: u64, n: u64) -> (Vec<Header>, Vec<alloy::primitives::Bytes>) {
        // Build oldest→newest so each parent_hash points at the prior hash.
        let mut hdrs: Vec<Header> = Vec::new();
        let mut prev_hash = B256::repeat_byte(0xEE); // arbitrary genesis-ish
        let lowest = top + 1 - n;
        for num in lowest..=top {
            let mut h = Header::default();
            h.number = num;
            h.parent_hash = prev_hash;
            prev_hash = h.hash_slow();
            hdrs.push(h);
        }
        hdrs.reverse(); // parent-first (highest number at index 0)
        let rlp: Vec<alloy::primitives::Bytes> = hdrs
            .iter()
            .map(|h| {
                let mut buf = Vec::new();
                h.encode(&mut buf);
                alloy::primitives::Bytes::from(buf)
            })
            .collect();
        (hdrs, rlp)
    }

    fn witness_with(headers: Vec<alloy::primitives::Bytes>) -> rpc::ExecutionWitness {
        rpc::ExecutionWitness {
            state: vec![],
            codes: vec![],
            keys: vec![],
            headers,
        }
    }

    fn parent_block(h: &Header) -> Block {
        Block {
            header: RpcHeader::new(h.clone()),
            ..Default::default()
        }
    }

    fn encode_headers(hdrs: &[Header]) -> Vec<alloy::primitives::Bytes> {
        hdrs.iter()
            .map(|h| {
                let mut buf = Vec::new();
                h.encode(&mut buf);
                alloy::primitives::Bytes::from(buf)
            })
            .collect()
    }

    #[test]
    fn contiguous_chain_is_emitted_parent_first() {
        let (hdrs, rlp) = chain(1000, 5); // 1000..996, parent-first
        let parent = parent_block(&hdrs[0]);
        let out = build_ancestors_from_witness(&witness_with(rlp), &parent);
        assert_eq!(out.len(), 5);
        // parent-first, descending, contiguous
        assert_eq!(out[0].header.number, 1000);
        assert_eq!(out[4].header.number, 996);
        for w in out.windows(2) {
            assert_eq!(w[0].header.number, w[1].header.number + 1);
        }
    }

    #[test]
    fn single_parent_only() {
        let (hdrs, rlp) = chain(1000, 1);
        let parent = parent_block(&hdrs[0]);
        let out = build_ancestors_from_witness(&witness_with(rlp), &parent);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].header.number, 1000);
    }

    #[test]
    fn sparse_set_is_accepted() {
        // Sparse: parent (1000) + a far ancestor (900), with a gap between.
        // Previously this fell back to the RPC walk; now the guest resolves
        // BLOCKHASH by number over the sparse set, so we emit it as-is.
        let (chain_hdrs, _) = chain(1000, 101); // 1000..900
        let parent = parent_block(&chain_hdrs[0]);
        let sparse = vec![chain_hdrs[0].clone(), chain_hdrs[100].clone()]; // 1000 & 900
        let out = build_ancestors_from_witness(&witness_with(encode_headers(&sparse)), &parent);
        // Both records present, parent-first, gap preserved (no filling).
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].header.number, 1000);
        assert_eq!(out[1].header.number, 900);
    }

    #[test]
    fn empty_headers_yields_parent_only() {
        // No BLOCKHASH ⇒ witness has no headers ⇒ result is just the parent
        // at index 0 (no RPC fallback any more).
        let (hdrs, _) = chain(1000, 1);
        let parent = parent_block(&hdrs[0]);
        let out = build_ancestors_from_witness(&witness_with(vec![]), &parent);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].header.number, 1000);
    }

    #[test]
    fn parent_is_always_index_zero() {
        // Witness headers are all deeper ancestors (none is the parent).
        // The parent Block must still land at index 0, ahead of them.
        let (hdrs, _) = chain(999, 3); // 999..997
        let parent_hdr = {
            let mut p = hdrs[0].clone();
            p.number = 1000;
            p
        };
        let parent = parent_block(&parent_hdr);
        let out = build_ancestors_from_witness(&witness_with(encode_headers(&hdrs)), &parent);
        assert_eq!(out[0].header.number, 1000); // parent first
        assert_eq!(out.len(), 4); // parent + 999, 998, 997
        assert_eq!(out[1].header.number, 999);
        assert_eq!(out[3].header.number, 997);
    }

    #[test]
    fn duplicate_of_parent_number_is_dropped() {
        // A witness header carrying the parent's own number must not
        // duplicate index 0 — the fetched parent Block is authoritative.
        let (hdrs, rlp) = chain(1000, 3); // 1000, 999, 998 (1000 == parent)
        let parent = parent_block(&hdrs[0]);
        let out = build_ancestors_from_witness(&witness_with(rlp), &parent);
        assert_eq!(out.len(), 3); // parent(1000) + 999 + 998, not 4
        assert_eq!(out[0].header.number, 1000);
        assert_eq!(
            out.iter().filter(|b| b.header.number == 1000).count(),
            1,
            "parent number must appear exactly once"
        );
    }
}

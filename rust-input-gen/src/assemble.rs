//! Assemble an `OfflineSources` bundle from parts a node already holds:
//! the block, its execution witness and the accounts/slots it accessed.
//!
//! The live-RPC path (`fetch`) fetches those parts over JSON-RPC; an
//! in-process consumer (the reth ExEx in `reth-zisk-exex/`) produces them
//! from the node's own state and calls `sources_from_parts` directly, so
//! both paths encode the same bytes for the same block.

use alloy::consensus::{Header, TxEnvelope};
use alloy::eips::eip4895::Withdrawal;
use alloy::primitives::{Address, B256};
use alloy::rpc::types::{Block, BlockTransactions, Header as RpcHeader, Transaction};
use anyhow::Result;
use tracing::info;

use crate::offline::OfflineSources;
use crate::rpc;
use crate::state_root::Accessed;

/// The `OfflineSources` of block `current` on chain `chain_id`.
///
/// `accessed` is every account and slot the block accesses (each becomes a
/// leaf in the StateRoot section, an empty one if the key doesn't exist).
/// `witness.keys` (an address followed by its slots), the beneficiary and
/// every withdrawal recipient are added to it here.
pub fn sources_from_parts(
    chain_id: u64,
    current: Block,
    witness: rpc::ExecutionWitness,
    mut accessed: Accessed,
) -> Result<OfflineSources> {
    add_witness_keys(&mut accessed, &witness, &current)?;

    // Parent header comes from the WITNESS: reth's witness carries every
    // ancestor header the block touched (parent + deeper BLOCKHASH targets)
    // in `witness.headers`, and its state trie root IS the pre-state root.
    let parent = parent_from_witness(&witness, current.header.parent_hash)?;
    info!(parent_state_root = %parent.header.state_root, "recovered parent header from witness");

    // Fork schedule is COMPILED IN per chain, not fetched — reth's client does
    // the same (baked chain config selected by chain id). NB: update
    // `fork_params` at each fork/BPO.
    let (is_osaka, blob_base_fee_update_fraction, target_blob_gas_per_block, max_blob_gas_per_block) =
        fork_params(chain_id, current.header.timestamp)?;
    if current.header.block_access_list_hash.is_some() {
        info!(timestamp = current.header.timestamp, "block runs under Amsterdam");
    } else if is_osaka {
        info!(timestamp = current.header.timestamp, "block runs under Osaka");
    }
    info!(
        blob_base_fee_update_fraction,
        chain_id, "resolved blob base-fee update fraction (compiled-in schedule)"
    );

    // PreviousBlocks: ancestor headers from `witness.headers`, parent first.
    let ancestors = build_ancestors_from_witness(&witness, &parent);
    info!(count = ancestors.len(), "built ancestor set (block+witness only)");

    // `prestate`/`diff`/`system_contract_slots` stay empty: they are only
    // populated by the manifest path; nothing in the witness-only encode path
    // consumes them.
    Ok(OfflineSources {
        current,
        parent,
        ancestors,
        prestate: rpc::Prestate::default(),
        diff: rpc::PrestateDiff::default(),
        witness,
        system_contract_slots: std::collections::BTreeSet::new(),
        is_osaka,
        blob_base_fee_update_fraction,
        target_blob_gas_per_block,
        max_blob_gas_per_block,
        accessed,
    })
}

/// An rpc `Block` (full transactions) from a consensus header and its
/// recovered transactions, the shape `OfflineSources::current` expects.
/// Only the fields the encoder reads are meaningful.
pub fn rpc_block(
    header: Header,
    transactions: impl IntoIterator<Item = (TxEnvelope, Address)>,
    withdrawals: Option<Vec<Withdrawal>>,
) -> Block {
    let hash = header.hash_slow();
    let number = header.number;
    let base_fee = header.base_fee_per_gas;
    let txs = transactions
        .into_iter()
        .enumerate()
        .map(|(i, (env, signer))| {
            let effective_gas_price =
                Some(alloy::consensus::Transaction::effective_gas_price(&env, base_fee));
            Transaction {
                inner: alloy::consensus::transaction::Recovered::new_unchecked(env, signer),
                block_hash: Some(hash),
                block_number: Some(number),
                block_timestamp: Some(header.timestamp),
                transaction_index: Some(i as u64),
                effective_gas_price,
            }
        })
        .collect();
    let mut block = Block::new(RpcHeader::new(header), BlockTransactions::Full(txs));
    block.withdrawals = withdrawals.map(Into::into);
    block
}

/// Keep only the bytecodes in `used_codes` (by keccak hash) and, besides
/// the parent, only the ancestors whose number is in `used_blocks`: what a
/// guest run reported with `ZEG_DUMP_USED`. For an input built from a
/// superset (from the BAL, without executing), so the proof doesn't pay to
/// hash codes and headers the block never reads.
pub fn trim(
    sources: &mut OfflineSources,
    used_codes: &std::collections::HashSet<B256>,
    used_blocks: &std::collections::BTreeSet<u64>,
) {
    sources.witness.codes.retain(|c| used_codes.contains(&alloy::primitives::keccak256(c)));
    let mut ancestors = std::mem::take(&mut sources.ancestors).into_iter();
    let parent = ancestors.next();
    sources.ancestors = parent
        .into_iter()
        .chain(ancestors.filter(|b| used_blocks.contains(&b.header.number)))
        .collect();
}

/// Add reth's witness keys (an address followed by its slots), the
/// beneficiary and the withdrawal recipients (credited outside any tx) to
/// `accessed`.
pub(crate) fn add_witness_keys(
    accessed: &mut Accessed,
    witness: &rpc::ExecutionWitness,
    current: &Block,
) -> Result<()> {
    let mut owner: Option<Address> = None;
    for key in &witness.keys {
        match key.len() {
            20 => {
                let addr = Address::from_slice(key);
                accessed.entry(addr).or_default();
                owner = Some(addr);
            }
            32 => {
                let Some(addr) = owner else {
                    anyhow::bail!("witness.keys: slot before any address");
                };
                accessed.entry(addr).or_default().insert(B256::from_slice(key));
            }
            n => anyhow::bail!("witness.keys: unexpected key length {n}"),
        }
    }
    accessed.entry(current.header.beneficiary).or_default();
    for wd in current.withdrawals.iter().flat_map(|w| w.iter()) {
        accessed.entry(wd.address).or_default();
    }
    Ok(())
}

/// Compiled-in fork schedule of the chain `chain_id` — returns `(is_osaka,
/// blob BASE_FEE_UPDATE_FRACTION, TARGET_BLOB_GAS_PER_BLOCK,
/// MAX_BLOB_GAS_PER_BLOCK)` for a block at `timestamp`. Mirrors reth's baked
/// chain config. Entries are (fork activation unix time,
/// base_fee_update_fraction, target_blob_count, max_blob_count), newest
/// first; pick the newest whose activation <= timestamp.
///
/// UPDATE THIS at each fork / blob-schedule (BPO) change.
///
/// Mainnet (chain id 1):
/// - BPO2   : 2026-01-07 (activationTime 1767747671), fraction 11684671, target 14, max 21
/// - BPO1   : 2025-12-09 (1765290071),                fraction 8346193,  target 10, max 15
/// - Prague : 2025-05-07 (1746612311),                fraction 5007716,  target 6,  max 9
/// - Cancun : 2024-03-13 (1710338135),                fraction 3338477,  target 3,  max 6
///
/// Sepolia (chain id 11155111). The Amsterdam row is the node's `eth_config`
/// (`current`); the earlier rows are the published Sepolia schedule. This
/// path only replays blocks within the node's recent-state window, so only
/// the newest row is exercised.
/// - Amsterdam : 1791294816, fraction 11684671, target 14, max 21
/// - BPO2      : 1761607008, fraction 11684671, target 14, max 21
/// - BPO1      : 1761017184, fraction 8346193,  target 10, max 15
/// - Osaka     : 1760427360 (blob schedule unchanged from Prague)
/// - Prague    : 1741159776, fraction 5007716,  target 6,  max 9
/// - Cancun    : 1706655072, fraction 3338477,  target 3,  max 6
///
/// `is_osaka` (EVM-revision dispatch) is tracked separately from the blob
/// schedule rows — Osaka itself doesn't change the blob target/fraction (only
/// the later BPO forks do). On mainnet it's approximated to BPO2's activation,
/// which is immaterial in practice since this path only ever replays blocks
/// within the node's ~32-block recent window (see CLAUDE.md). Amsterdam needs
/// no flag: the guest detects it from the header's block_access_list_hash.
pub fn fork_params(chain_id: u64, timestamp: u64) -> Result<(bool, u64, u64, u64)> {
    const GAS_PER_BLOB: u64 = 131_072;
    // (osaka_activation, schedule) per chain; schedule rows are
    // (activation_time, base_fee_update_fraction, target_blob_count, max_blob_count).
    let (osaka_activation, schedule): (u64, &[(u64, u64, u64, u64)]) = match chain_id {
        1 => (
            1767747671,
            &[
                (1767747671, 11684671, 14, 21), // BPO2
                (1765290071, 8346193, 10, 15),  // BPO1
                (1746612311, 5007716, 6, 9),    // Prague
                (1710338135, 3338477, 3, 6),    // Cancun
            ],
        ),
        11155111 => (
            1760427360,
            &[
                (1791294816, 11684671, 14, 21), // Amsterdam
                (1761607008, 11684671, 14, 21), // BPO2
                (1761017184, 8346193, 10, 15),  // BPO1
                (1741159776, 5007716, 6, 9),    // Prague
                (1706655072, 3338477, 3, 6),    // Cancun
            ],
        ),
        id => anyhow::bail!("no compiled-in fork schedule for chain id {id}"),
    };
    let is_osaka = timestamp >= osaka_activation;
    let (fraction, target_blobs, max_blobs) = schedule
        .iter()
        .find(|(act, _, _, _)| timestamp >= *act)
        .map(|(_, f, t, m)| (*f, *t, *m))
        .unwrap_or((0, 0, 0)); // pre-Cancun: no blob schedule → guest default
    Ok((is_osaka, fraction, target_blobs * GAS_PER_BLOB, max_blobs * GAS_PER_BLOB))
}

/// Recover the parent `Block` from `witness.headers` — the RLP header whose
/// keccak hash equals `parent_hash` (from the trusted, anchored `current`
/// block, so it pins exactly which header is accepted). reth's witness always
/// carries the parent (the block reads its parent hash), and the header's
/// `state_root` is the pre-state root anchor. No RPC, no fallback: a witness
/// that omits the parent is a hard input-completeness error (matching reth,
/// whose stateless validator is a pure function of the witness).
fn parent_from_witness(witness: &rpc::ExecutionWitness, parent_hash: B256) -> Result<Block> {
    use alloy::rlp::Decodable;

    for raw in &witness.headers {
        let mut slice: &[u8] = raw.as_ref();
        if let Ok(h) = Header::decode(&mut slice) {
            if h.hash_slow() == parent_hash {
                return Ok(Block { header: RpcHeader::new(h), ..Default::default() });
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
/// The caller passes a CONTIGUOUS `witness.headers` (the RPC path backfills it
/// to a full parent_hash-linked chain from the parent down to the deepest
/// BLOCKHASH target; see `fetch.rs`). The cpp-guest serves BLOCKHASH from this
/// chain and verifies the whole list is contiguous and linked, so a sparse set
/// would make a deep BLOCKHASH unprovable. This function only orders/dedups the
/// headers parent-first; it does not itself enforce contiguity.
///
/// Index 0 is always the already-recovered parent `Block` (it carries the
/// anchor the guest checks against `ConsensusInfo::parent_hash`). If
/// `witness.headers` is empty (the block did no BLOCKHASH), the result is the
/// single-element `[parent]` list. Any header that fails to RLP-decode is
/// skipped; the parent is always index 0 regardless.
fn build_ancestors_from_witness(witness: &rpc::ExecutionWitness, parent: &Block) -> Vec<Block> {
    use alloy::rlp::Decodable;

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
    // Block, then append every OTHER witness header (dropping any duplicate
    // of the parent's number — the parent Block is authoritative for that
    // slot).
    let mut out: Vec<Block> = Vec::with_capacity(headers.len() + 1);
    out.push(parent.clone());
    for h in headers.into_iter() {
        if h.number == parent_number {
            continue;
        }
        // Wrap the consensus header in an rpc Block (empty txs — the section
        // writer only reads header fields).
        out.push(Block { header: RpcHeader::new(h), ..Default::default() });
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

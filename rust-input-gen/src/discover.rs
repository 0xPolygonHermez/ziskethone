//! Pre-walk the state + storage MPTs to surface untouched-sibling
//! leaves that share trie prefixes with our touched keys.
//!
//! The state-root reconstruction in cpp-guest's StateRoot walker
//! requires every leaf that occupies a position on the walked paths.
//! When a new account / new storage slot is inserted into the trie,
//! the existing sibling leaf at the would-be insertion point must be
//! re-positioned in the reconstructed structure — which means its
//! pre-image must be in our Accounts / Storages table.
//!
//! This module performs a one-shot walk that records each such
//! sibling. Callers inject the resulting entries into prestate as
//! is_read_only entries (block-start values come straight from the
//! leaf RLP).

use std::collections::HashMap;

use alloy::primitives::{Address, Bytes, B256, U256};
use anyhow::{anyhow, bail, Context, Result};

use crate::mpt::{self, hp_decode, keccak256, nibbles_of, Rlp};
use crate::rpc::{AccountPrestate, ExecutionWitness, Prestate, PrestateDiff};

/// Inject untouched-sibling leaves discovered along the touched-key
/// paths into `prestate`. Mutates `prestate` in place. The injected
/// entries:
///   * Accounts: balance / nonce / code-from-witness, never written —
///     `diff` is NOT modified, so write_accounts assigns is_read_only=1.
///   * Storages: slot value from the leaf RLP, also never written.
pub fn enrich_prestate_from_witness(
    prestate: &mut Prestate,
    diff: &PrestateDiff,
    witness: &ExecutionWitness,
    parent_state_root: B256,
) -> Result<DiscoverStats> {
    // Build node map (keccak256 -> raw RLP). Entries < 32 B can't be
    // referenced by hash so we skip them.
    let mut nodes: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(witness.state.len());
    for raw in &witness.state {
        if raw.len() < 32 {
            continue;
        }
        let h = keccak256(raw);
        nodes.insert(h, raw.to_vec());
    }

    // Pre-image map: keccak(addr) -> addr, keccak(slot) -> slot.
    let mut preimage_addr: HashMap<[u8; 32], Address> = HashMap::new();
    let mut preimage_slot: HashMap<[u8; 32], B256> = HashMap::new();
    for k in &witness.keys {
        let h = keccak256(k);
        match k.len() {
            20 => {
                preimage_addr.insert(h, Address::from_slice(k));
            }
            32 => {
                preimage_slot.insert(h, B256::from_slice(k));
            }
            _ => {} // ignore other sizes
        }
    }

    // Code map: keccak256(code) -> code bytes — for injecting code on
    // sibling accounts that carry code on chain.
    let mut codes_by_hash: HashMap<[u8; 32], Bytes> = HashMap::new();
    for c in &witness.codes {
        codes_by_hash.insert(keccak256(c), c.clone());
    }

    let mut ctx = Ctx {
        nodes: &nodes,
        preimage_addr: &preimage_addr,
        preimage_slot: &preimage_slot,
        codes_by_hash: &codes_by_hash,
        prestate,
        diff,
        stats: DiscoverStats::default(),
    };

    // Targets for the state trie pre-walk: keccak(addr) for every
    // address currently in the prestate (BTreeMap iteration → no order
    // dependency here since we only need set semantics).
    let state_targets: Vec<[u8; 32]> = ctx
        .prestate
        .keys()
        .map(|a| keccak256(a.as_slice()))
        .collect();
    let state_targets = sorted_unique(state_targets);

    walk_state(&mut ctx, parent_state_root.0, &[], &state_targets)?;

    Ok(ctx.stats)
}

#[derive(Default, Debug)]
pub struct DiscoverStats {
    pub extra_accounts: usize,
    pub extra_slots:    usize,
}

struct Ctx<'a> {
    nodes:         &'a HashMap<[u8; 32], Vec<u8>>,
    preimage_addr: &'a HashMap<[u8; 32], Address>,
    preimage_slot: &'a HashMap<[u8; 32], B256>,
    codes_by_hash: &'a HashMap<[u8; 32], Bytes>,
    prestate:      &'a mut Prestate,
    diff:          &'a PrestateDiff,
    stats:         DiscoverStats,
}

fn sorted_unique<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort();
    v.dedup();
    v
}

fn nibble_at(hash: &[u8; 32], i: usize) -> u8 {
    let b = hash[i / 2];
    if i % 2 == 0 { b >> 4 } else { b & 0x0f }
}

// ===== state-trie walker =====================================================

fn walk_state(
    ctx: &mut Ctx,
    node_hash: [u8; 32],
    walked: &[u8],
    targets: &[[u8; 32]],
) -> Result<()> {
    if targets.is_empty() {
        return Ok(());
    }
    let raw = ctx
        .nodes
        .get(&node_hash)
        .ok_or_else(|| {
            anyhow!(
                "discover: witness missing state node 0x{} at depth {}",
                hex::encode(node_hash),
                walked.len()
            )
        })?
        .clone();
    walk_state_raw(ctx, &raw, walked, targets)
}

fn walk_state_raw(
    ctx: &mut Ctx,
    raw: &[u8],
    walked: &[u8],
    targets: &[[u8; 32]],
) -> Result<()> {
    let (item, _) = Rlp::decode(raw).context("discover: decoding state node")?;
    let items = item.as_list().context("discover: state node not a list")?;
    match items.len() {
        17 => {
            let mut buckets: Vec<Vec<[u8; 32]>> = (0..16).map(|_| Vec::new()).collect();
            for t in targets {
                let n = nibble_at(t, walked.len()) as usize;
                buckets[n].push(*t);
            }
            let mut walked_child = walked.to_vec();
            walked_child.push(0);
            for i in 0..16 {
                if buckets[i].is_empty() {
                    continue;
                }
                *walked_child.last_mut().unwrap() = i as u8;
                match &items[i] {
                    Rlp::Bytes(b) if b.is_empty() => {
                        // Insertion into an empty slot — fine.
                    }
                    Rlp::Bytes(b) if b.len() == 32 => {
                        let h = <[u8; 32]>::try_from(*b).unwrap();
                        walk_state(ctx, h, &walked_child, &buckets[i])?;
                    }
                    Rlp::Bytes(b) => {
                        bail!("discover: state branch child wrong length {}", b.len());
                    }
                    Rlp::List(_) => {
                        let buf = encode_inline(&items[i]);
                        walk_state_raw(ctx, &buf, &walked_child, &buckets[i])?;
                    }
                }
            }
            Ok(())
        }
        2 => {
            let path = items[0].as_bytes()?;
            let (nibs, is_leaf) = hp_decode(path);
            if is_leaf {
                // State-trie leaf at walked + nibs. Full key = 64 nibbles.
                let mut full = walked.to_vec();
                full.extend_from_slice(&nibs);
                if full.len() != 64 {
                    bail!("discover: state leaf path total = {}", full.len());
                }
                let leaf_full: [u8; 32] = nibbles_to_bytes(&full);
                let is_target = targets.iter().any(|t| t == &leaf_full);
                if !is_target {
                    inject_sibling_account(ctx, leaf_full, &items[1])?;
                }
                Ok(())
            } else {
                // Extension — all targets must take it (otherwise we
                // have a divergent extension, which Phase 5 v1 ignores
                // since the discovery pass only enriches read-only
                // sibling leaves and doesn't enroll extensions).
                let walked_after: Vec<u8> = walked
                    .iter()
                    .chain(nibs.iter())
                    .copied()
                    .collect();
                let take: Vec<[u8; 32]> = targets
                    .iter()
                    .copied()
                    .filter(|t| {
                        nibs.iter().enumerate().all(|(i, en)| {
                            nibble_at(t, walked.len() + i) == *en
                        })
                    })
                    .collect();
                if take.is_empty() {
                    return Ok(());
                }
                match &items[1] {
                    Rlp::Bytes(b) if b.len() == 32 => {
                        walk_state(ctx, <[u8; 32]>::try_from(*b).unwrap(), &walked_after, &take)
                    }
                    Rlp::Bytes(b) => {
                        bail!("discover: extension child wrong length {}", b.len())
                    }
                    Rlp::List(_) => {
                        let buf = encode_inline(&items[1]);
                        walk_state_raw(ctx, &buf, &walked_after, &take)
                    }
                }
            }
        }
        n => bail!("discover: unexpected state node shape (items={})", n),
    }
}

fn inject_sibling_account(
    ctx: &mut Ctx,
    addr_hash: [u8; 32],
    value: &Rlp<'_>,
) -> Result<()> {
    let value_bytes = value.as_bytes().context("state leaf value not bytes")?;
    let (acct, _) = Rlp::decode(value_bytes).context("decoding sibling-account RLP")?;
    let fields = acct.as_list()?;
    if fields.len() != 4 {
        bail!("sibling account: expected 4 fields, got {}", fields.len());
    }
    let addr = match ctx.preimage_addr.get(&addr_hash) {
        Some(a) => *a,
        None => bail!(
            "discover: no preimage for sibling account 0x{}",
            hex::encode(addr_hash)
        ),
    };
    if ctx.prestate.contains_key(&addr) {
        return Ok(()); // already known
    }
    let nonce = rlp_uint::<u64>(fields[0].as_bytes()?);
    let balance = rlp_uint_be32(fields[1].as_bytes()?);
    let code_hash_bytes = fields[3].as_bytes()?;
    let code_hash: [u8; 32] = code_hash_bytes
        .try_into()
        .map_err(|_| anyhow!("sibling account: code_hash wrong length"))?;

    let code = if code_hash == EMPTY_CODE_HASH_BYTES {
        None
    } else {
        ctx.codes_by_hash.get(&code_hash).cloned()
    };

    ctx.prestate.insert(
        addr,
        AccountPrestate {
            balance: Some(U256::from_be_bytes(balance)),
            nonce: Some(nonce),
            code,
            storage: Default::default(),
        },
    );
    let _ = ctx.diff; // not modified — sibling entries are read-only
    ctx.stats.extra_accounts += 1;
    Ok(())
}

// ===== misc helpers ==========================================================

fn nibbles_to_bytes(nibs: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, n) in nibs.iter().enumerate() {
        if i % 2 == 0 {
            out[i / 2] |= (n & 0x0f) << 4;
        } else {
            out[i / 2] |= n & 0x0f;
        }
    }
    out
}

fn rlp_uint<T>(b: &[u8]) -> T
where
    T: TryFrom<u128> + From<u8> + Copy,
    <T as TryFrom<u128>>::Error: std::fmt::Debug,
{
    if b.is_empty() {
        return T::from(0);
    }
    let mut acc: u128 = 0;
    for &c in b {
        acc = (acc << 8) | (c as u128);
    }
    T::try_from(acc).expect("rlp_uint: value too large for target type")
}

fn rlp_uint_be32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(b.len());
    out[start..].copy_from_slice(b);
    out
}

fn encode_inline(item: &Rlp<'_>) -> Vec<u8> {
    match item {
        Rlp::Bytes(b) => {
            if b.len() == 1 && b[0] < 0x80 {
                return b.to_vec();
            }
            let mut out = Vec::with_capacity(b.len() + 9);
            if b.len() < 56 {
                out.push(0x80 + b.len() as u8);
            } else {
                let lb = be_bytes(b.len() as u64);
                out.push(0xb7 + lb.len() as u8);
                out.extend_from_slice(&lb);
            }
            out.extend_from_slice(b);
            out
        }
        Rlp::List(items) => {
            let mut payload = Vec::new();
            for it in items {
                payload.extend_from_slice(&encode_inline(it));
            }
            let mut out = Vec::with_capacity(payload.len() + 9);
            if payload.len() < 56 {
                out.push(0xc0 + payload.len() as u8);
            } else {
                let lb = be_bytes(payload.len() as u64);
                out.push(0xf7 + lb.len() as u8);
                out.extend_from_slice(&lb);
            }
            out.extend_from_slice(&payload);
            out
        }
    }
}

fn be_bytes(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    out.reverse();
    out
}

// keccak256("")
const EMPTY_CODE_HASH_BYTES: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

// Suppress unused warnings from helpers retained for future
// storage-trie expansion.
#[allow(dead_code)]
fn _unused() {
    let _ = mpt::account_storage_root;
}

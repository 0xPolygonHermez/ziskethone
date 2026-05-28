//! Post-gen consistency check.
//!
//! Walks the canonical parent state trie reconstructed from the
//! witness, looks up each account in our touch set, and compares the
//! on-chain RLP fields (nonce / balance / storage_root / code_hash)
//! against what we encoded. Same comparison for touched storage slots.
//!
//! Mismatch printouts pin down which Account / Storage entry is
//! mis-valued — the root cause of `pre-execution state root mismatch`.

use std::collections::HashMap;

use alloy::primitives::{Address, B256, U256};
use anyhow::{anyhow, bail, Context, Result};
use sha3::{Digest, Keccak256};
use tracing::{info, warn};

use crate::mpt::{hp_decode, keccak256, Rlp};
use crate::rpc::{ExecutionWitness, Prestate, PrestateDiff};
use crate::touchset::TouchSet;

pub fn check(
    parent_state_root: B256,
    witness: &ExecutionWitness,
    prestate: &Prestate,
    diff: &PrestateDiff,
    touch: &TouchSet,
) -> Result<()> {
    let mut nodes: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(witness.state.len());
    for raw in &witness.state {
        if raw.len() < 32 {
            continue;
        }
        nodes.insert(keccak256(raw), raw.to_vec());
    }

    let mut state_mismatch = 0;
    let mut state_absent_in_chain = 0;
    let mut storage_mismatch = 0;
    let mut storage_absent_in_chain = 0;

    for (i, addr) in touch.addrs.iter().enumerate() {
        let addr_hash = keccak256(addr.as_slice());
        let chain_leaf = walk_to_leaf(&nodes, &parent_state_root.0, &addr_hash)?;

        // Our written values (matches sections::write_accounts).
        let created_this_block =
            !diff.pre.contains_key(addr) && diff.post.contains_key(addr);
        let (our_balance, our_nonce, our_code_hash): (U256, u64, [u8; 32]) =
            if created_this_block {
                (U256::ZERO, 0u64, EMPTY_CODE_HASH)
            } else {
                let ps_main = prestate.get(addr);
                let ps_fallback = diff.pre.get(addr);
                let bal = ps_main
                    .and_then(|p| p.balance)
                    .or_else(|| ps_fallback.and_then(|p| p.balance))
                    .unwrap_or(U256::ZERO);
                let nonce = ps_main
                    .and_then(|p| p.nonce)
                    .or_else(|| ps_fallback.and_then(|p| p.nonce))
                    .unwrap_or(0);
                let code = ps_main
                    .and_then(|p| p.code.as_ref())
                    .or_else(|| ps_fallback.and_then(|p| p.code.as_ref()));
                let chash: [u8; 32] = match code {
                    Some(c) if !c.is_empty() => keccak256(c),
                    _ => EMPTY_CODE_HASH,
                };
                (bal, nonce, chash)
            };

        let chain_account = match chain_leaf {
            Some(v) => v,
            None => {
                // Account doesn't exist in the parent state trie. For
                // the old-pass to match, our values must yield an empty
                // account (`is_empty_account` returns true).
                let empty = our_nonce == 0
                    && our_balance == U256::ZERO
                    && our_code_hash == EMPTY_CODE_HASH;
                if !empty {
                    warn!(
                        idx = i,
                        addr = %addr,
                        nonce = our_nonce,
                        balance = %our_balance,
                        code_hash = %B256::from(our_code_hash),
                        "account NOT in parent trie but we wrote non-empty values — old root will mismatch",
                    );
                    state_absent_in_chain += 1;
                }
                continue;
            }
        };

        let (chain_nonce, chain_balance, chain_storage_root, chain_code_hash) =
            decode_account_rlp(&chain_account)?;

        if chain_nonce != our_nonce
            || chain_balance != our_balance
            || chain_code_hash != our_code_hash
        {
            warn!(
                idx = i,
                addr = %addr,
                chain_nonce = chain_nonce,
                our_nonce = our_nonce,
                chain_balance = %chain_balance,
                our_balance = %our_balance,
                chain_code_hash = %B256::from(chain_code_hash),
                our_code_hash = %B256::from(our_code_hash),
                "state account VALUE mismatch",
            );
            state_mismatch += 1;
        }

        // Storage subtree check for this account.
        let touched_slots: Vec<(B256, usize)> = touch.slots_for(addr);
        if touched_slots.is_empty() {
            continue;
        }
        for (slot, sidx) in touched_slots {
            let slot_hash = keccak256(slot.as_slice());
            let chain_slot_leaf =
                walk_to_leaf(&nodes, &chain_storage_root, &slot_hash)?;

            // Our written storage value (matches sections::write_storages).
            let our_value: B256 = pick_storage_value(prestate, diff, addr, &slot);

            let chain_value = match chain_slot_leaf.as_ref() {
                Some(v) => decode_storage_value_rlp(v)?,
                None => B256::ZERO,
            };

            if our_value != chain_value {
                warn!(
                    idx = sidx,
                    addr = %addr,
                    slot = %slot,
                    chain = %chain_value,
                    ours = %our_value,
                    "storage VALUE mismatch",
                );
                storage_mismatch += 1;
                if chain_slot_leaf.is_none() && our_value != B256::ZERO {
                    storage_absent_in_chain += 1;
                }
            }
        }
    }

    info!(
        state_mismatches = state_mismatch,
        state_phantom = state_absent_in_chain,
        storage_mismatches = storage_mismatch,
        storage_phantom = storage_absent_in_chain,
        "verifier summary",
    );
    Ok(())
}

fn pick_storage_value(
    prestate: &Prestate,
    diff: &PrestateDiff,
    addr: &Address,
    slot: &B256,
) -> B256 {
    if let Some(ps) = prestate.get(addr) {
        if let Some(v) = ps.storage.get(slot) {
            return *v;
        }
    }
    if let Some(ps) = diff.pre.get(addr) {
        if let Some(v) = ps.storage.get(slot) {
            return *v;
        }
    }
    B256::ZERO
}

// ===== MPT walk =============================================================

fn walk_to_leaf(
    nodes: &HashMap<[u8; 32], Vec<u8>>,
    root: &[u8; 32],
    key: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    // Empty-trie root → key is absent.
    if root == &EMPTY_TRIE_ROOT {
        return Ok(None);
    }
    let raw = nodes
        .get(root)
        .ok_or_else(|| anyhow!("walk_to_leaf: witness missing root 0x{}", hex::encode(root)))?
        .clone();
    walk_raw(nodes, &raw, key, 0)
}

fn walk_raw(
    nodes: &HashMap<[u8; 32], Vec<u8>>,
    raw: &[u8],
    key: &[u8; 32],
    depth: usize,
) -> Result<Option<Vec<u8>>> {
    let (item, _) = Rlp::decode(raw).context("walk: decode")?;
    let items = item.as_list().context("walk: not a list")?;
    match items.len() {
        17 => {
            let nib = nibble(key, depth) as usize;
            follow_child(nodes, &items[nib], key, depth + 1)
        }
        2 => {
            let path = items[0].as_bytes()?;
            let (path_nibs, is_leaf) = hp_decode(path);
            for (i, p) in path_nibs.iter().enumerate() {
                if nibble(key, depth + i) != *p {
                    return Ok(None);
                }
            }
            if is_leaf {
                if depth + path_nibs.len() != 64 {
                    bail!(
                        "leaf path doesn't terminate at depth 64 (depth={}, path_nibs={})",
                        depth,
                        path_nibs.len()
                    );
                }
                Ok(Some(items[1].as_bytes()?.to_vec()))
            } else {
                follow_child(nodes, &items[1], key, depth + path_nibs.len())
            }
        }
        n => bail!("walk: unexpected MPT node shape (items={})", n),
    }
}

fn follow_child(
    nodes: &HashMap<[u8; 32], Vec<u8>>,
    child: &Rlp<'_>,
    key: &[u8; 32],
    depth: usize,
) -> Result<Option<Vec<u8>>> {
    match child {
        Rlp::Bytes(b) if b.is_empty() => Ok(None),
        Rlp::Bytes(b) if b.len() == 32 => {
            let h = <[u8; 32]>::try_from(*b).unwrap();
            let raw = nodes
                .get(&h)
                .ok_or_else(|| anyhow!("follow: witness missing 0x{}", hex::encode(h)))?
                .clone();
            walk_raw(nodes, &raw, key, depth)
        }
        Rlp::Bytes(b) => bail!("follow: child bytes wrong length {}", b.len()),
        Rlp::List(_) => {
            // Inline child — re-encode and walk in-place.
            let buf = encode_inline(child);
            walk_raw(nodes, &buf, key, depth)
        }
    }
}

fn nibble(hash: &[u8; 32], i: usize) -> u8 {
    let b = hash[i / 2];
    if i % 2 == 0 {
        b >> 4
    } else {
        b & 0x0f
    }
}

// ===== RLP decoders =========================================================

fn decode_account_rlp(b: &[u8]) -> Result<(u64, U256, [u8; 32], [u8; 32])> {
    let (item, _) = Rlp::decode(b)?;
    let fields = item.as_list()?;
    if fields.len() != 4 {
        bail!("account RLP: expected 4 fields, got {}", fields.len());
    }
    let nonce = decode_rlp_u64(fields[0].as_bytes()?);
    let balance = decode_rlp_u256(fields[1].as_bytes()?);
    let sroot: [u8; 32] = fields[2]
        .as_bytes()?
        .try_into()
        .map_err(|_| anyhow!("storage_root wrong len"))?;
    let chash: [u8; 32] = fields[3]
        .as_bytes()?
        .try_into()
        .map_err(|_| anyhow!("code_hash wrong len"))?;
    Ok((nonce, balance, sroot, chash))
}

fn decode_storage_value_rlp(b: &[u8]) -> Result<B256> {
    let (item, _) = Rlp::decode(b)?;
    let bytes = item.as_bytes()?;
    if bytes.len() > 32 {
        bail!("storage value RLP: > 32 bytes ({})", bytes.len());
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(B256::from(out))
}

fn decode_rlp_u64(b: &[u8]) -> u64 {
    let mut acc: u64 = 0;
    for &c in b {
        acc = (acc << 8) | (c as u64);
    }
    acc
}

fn decode_rlp_u256(b: &[u8]) -> U256 {
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    U256::from_be_bytes(out)
}

// ===== Inline-RLP helpers ===================================================

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

// ===== constants ============================================================

const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

// Suppress unused warnings.
#[allow(dead_code)]
fn _keep_imports() -> Keccak256 {
    Keccak256::new()
}

//! Witness-driven prestate enrichment.
//!
//! Walks the canonical parent state trie from the witness and patches
//! `prestate` so each touched account's block-start values (nonce /
//! balance / code) match the chain authoritatively. The prestate
//! tracer omits fields the txs in this block didn't touch (e.g. it
//! won't include `code` for an EIP-7702 delegated EOA whose code was
//! never EXTCODE-read), and our `write_accounts` then mis-defaults to
//! EMPTY_CODE_HASH — wrong for the post-execution state-root
//! reconstruction.

use std::collections::HashMap;

use alloy::primitives::{Address, Bytes, B256, U256};
use anyhow::{anyhow, bail, Context, Result};
use tracing::info;

use crate::mpt::{hp_decode, keccak256, Rlp};
use crate::rpc::{self, ExecutionWitness, Prestate};

pub async fn enrich_prestate_from_witness(
    client: &rpc::Client,
    parent_state_root: B256,
    block: u64,
    witness: &ExecutionWitness,
    prestate: &mut Prestate,
) -> Result<usize> {
    let mut nodes: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(witness.state.len());
    for raw in &witness.state {
        if raw.len() < 32 {
            continue;
        }
        nodes.insert(keccak256(raw), raw.to_vec());
    }
    // codes_by_hash: keccak(code) -> raw code bytes. Source for code
    // bodies missing from the prestate.
    let mut codes_by_hash: HashMap<[u8; 32], Bytes> = HashMap::new();
    for c in &witness.codes {
        codes_by_hash.insert(keccak256(c), c.clone());
    }

    let mut patched = 0usize;
    let addrs: Vec<Address> = prestate.keys().copied().collect();
    for addr in addrs {
        let addr_hash = keccak256(addr.as_slice());
        let leaf = match walk_to_leaf(&nodes, &parent_state_root.0, &addr_hash)? {
            Some(v) => v,
            None => continue, // account doesn't exist in parent trie
        };
        let (nonce, balance, _sroot, code_hash) = decode_account_rlp(&leaf)?;

        let entry = prestate.get_mut(&addr).unwrap();
        let mut touched = false;
        if entry.nonce.is_none() || entry.nonce != Some(nonce) {
            entry.nonce = Some(nonce);
            touched = true;
        }
        if entry.balance.is_none() || entry.balance != Some(balance) {
            entry.balance = Some(balance);
            touched = true;
        }
        // code_hash patching: if chain has non-empty code and we don't
        // have it (or have wrong code), pull it from witness `codes` or
        // fetch via eth_getCode.
        let our_chash = entry
            .code
            .as_ref()
            .filter(|c| !c.is_empty())
            .map(|c| keccak256(c))
            .unwrap_or(EMPTY_CODE_HASH);
        if our_chash != code_hash {
            if code_hash == EMPTY_CODE_HASH {
                entry.code = None;
            } else if let Some(c) = codes_by_hash.get(&code_hash) {
                entry.code = Some(c.clone());
            } else {
                // Not in witness.codes — fetch from chain.
                let c = client.code(addr, block - 1).await?;
                if keccak256(&c) != code_hash {
                    bail!(
                        "enrich: eth_getCode for {} returned code hashing to {} != chain leaf's {}",
                        addr,
                        hex::encode(keccak256(&c)),
                        hex::encode(code_hash)
                    );
                }
                entry.code = Some(c);
            }
            touched = true;
        }
        if touched {
            patched += 1;
        }
    }

    info!(patched_accounts = patched, "enriched prestate from witness");
    Ok(patched)
}

// ===== MPT walk + RLP =======================================================

fn walk_to_leaf(
    nodes: &HashMap<[u8; 32], Vec<u8>>,
    root: &[u8; 32],
    key: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    if root == &EMPTY_TRIE_ROOT {
        return Ok(None);
    }
    let raw = nodes
        .get(root)
        .ok_or_else(|| anyhow!("enrich: witness missing root 0x{}", hex::encode(root)))?
        .clone();
    walk_raw(nodes, &raw, key, 0)
}

fn walk_raw(
    nodes: &HashMap<[u8; 32], Vec<u8>>,
    raw: &[u8],
    key: &[u8; 32],
    depth: usize,
) -> Result<Option<Vec<u8>>> {
    let (item, _) = Rlp::decode(raw)?;
    let items = item.as_list()?;
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
                Ok(Some(items[1].as_bytes()?.to_vec()))
            } else {
                follow_child(nodes, &items[1], key, depth + path_nibs.len())
            }
        }
        _ => bail!("enrich: bad MPT shape"),
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
                .ok_or_else(|| anyhow!("enrich: missing 0x{}", hex::encode(h)))?
                .clone();
            walk_raw(nodes, &raw, key, depth)
        }
        Rlp::Bytes(b) => bail!("enrich: bad child len {}", b.len()),
        Rlp::List(_) => {
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

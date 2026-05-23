//! Minimal Merkle Patricia Trie walker for `debug_executionWitness` data.
//!
//! Only what we need: keccak256, a tiny RLP item decoder, hex-prefix path
//! decoding, and a `lookup` that walks a witness-backed trie from a root
//! hash along a 32-byte key. We never construct or mutate tries — only read.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use sha3::{Digest, Keccak256};

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

/// A decoded RLP item: either raw bytes (a string) or a list of items.
#[derive(Debug)]
pub enum Rlp<'a> {
    Bytes(&'a [u8]),
    List(Vec<Rlp<'a>>),
}

impl<'a> Rlp<'a> {
    /// Decode the RLP item at the start of `data`. Returns the item plus how
    /// many bytes were consumed.
    pub fn decode(data: &'a [u8]) -> Result<(Rlp<'a>, usize)> {
        if data.is_empty() {
            return Err(anyhow!("RLP: empty input"));
        }
        let b = data[0];
        if b < 0x80 {
            Ok((Rlp::Bytes(&data[..1]), 1))
        } else if b < 0xb8 {
            let len = (b - 0x80) as usize;
            if data.len() < 1 + len {
                return Err(anyhow!("RLP: short string truncated"));
            }
            Ok((Rlp::Bytes(&data[1..1 + len]), 1 + len))
        } else if b < 0xc0 {
            let len_of_len = (b - 0xb7) as usize;
            if data.len() < 1 + len_of_len {
                return Err(anyhow!("RLP: long string len truncated"));
            }
            let len = read_be(&data[1..1 + len_of_len])?;
            let total = 1 + len_of_len + len;
            if data.len() < total {
                return Err(anyhow!("RLP: long string body truncated"));
            }
            Ok((Rlp::Bytes(&data[1 + len_of_len..total]), total))
        } else if b < 0xf8 {
            let len = (b - 0xc0) as usize;
            let body = &data[1..1 + len];
            let items = decode_items(body)?;
            Ok((Rlp::List(items), 1 + len))
        } else {
            let len_of_len = (b - 0xf7) as usize;
            if data.len() < 1 + len_of_len {
                return Err(anyhow!("RLP: long list len truncated"));
            }
            let len = read_be(&data[1..1 + len_of_len])?;
            let total = 1 + len_of_len + len;
            if data.len() < total {
                return Err(anyhow!("RLP: long list body truncated"));
            }
            let items = decode_items(&data[1 + len_of_len..total])?;
            Ok((Rlp::List(items), total))
        }
    }

    pub fn as_bytes(&self) -> Result<&'a [u8]> {
        match self {
            Rlp::Bytes(b) => Ok(b),
            Rlp::List(_) => Err(anyhow!("RLP: expected bytes, got list")),
        }
    }

    pub fn as_list(&self) -> Result<&[Rlp<'a>]> {
        match self {
            Rlp::List(items) => Ok(items),
            Rlp::Bytes(_) => Err(anyhow!("RLP: expected list, got bytes")),
        }
    }
}

fn decode_items(mut body: &[u8]) -> Result<Vec<Rlp<'_>>> {
    let mut items = Vec::new();
    while !body.is_empty() {
        let (item, n) = Rlp::decode(body)?;
        items.push(item);
        body = &body[n..];
    }
    Ok(items)
}

fn read_be(bytes: &[u8]) -> Result<usize> {
    if bytes.len() > std::mem::size_of::<usize>() {
        return Err(anyhow!("RLP: length doesn't fit in usize"));
    }
    let mut acc = 0usize;
    for &b in bytes {
        acc = (acc << 8) | (b as usize);
    }
    Ok(acc)
}

/// Hex-prefix decode → (nibbles along this segment, is_leaf flag).
fn hp_decode(encoded: &[u8]) -> (Vec<u8>, bool) {
    if encoded.is_empty() {
        return (Vec::new(), false);
    }
    let flag = encoded[0];
    let odd = (flag >> 4) & 1 == 1;
    let is_leaf = (flag >> 5) & 1 == 1;
    let mut nibbles = Vec::with_capacity(2 * encoded.len());
    if odd {
        nibbles.push(flag & 0x0f);
    }
    for &byte in &encoded[1..] {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    (nibbles, is_leaf)
}

fn nibbles_of(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * bytes.len());
    for &b in bytes {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

/// Outcome of a trie walk.
#[derive(Debug)]
pub enum Lookup<'a> {
    /// Path resolved to a leaf with matching key — value bytes returned.
    Found(&'a [u8]),
    /// Path is provably absent (empty branch slot, divergent extension, or
    /// non-matching leaf — all valid MPT non-existence terminators).
    Absent,
    /// Walk hit a node hash that isn't in the witness. The witness doesn't
    /// cover this path → the EVM never traced it. Used as a signal to skip
    /// this candidate during slot attribution.
    NotInWitness,
}

/// Walk a trie rooted at `root` along `keccak256(key)` using `nodes` as the
/// node store (`hash -> raw RLP bytes`).
pub fn lookup<'a>(
    nodes: &'a HashMap<[u8; 32], Vec<u8>>,
    root: [u8; 32],
    key: &[u8],
) -> Result<Lookup<'a>> {
    let path_hash = keccak256(key);
    let remaining = nibbles_of(&path_hash);
    let raw = match nodes.get(&root) {
        Some(n) => n.as_slice(),
        None => return Ok(Lookup::NotInWitness),
    };
    walk_node(nodes, raw, remaining)
}

/// Walk starting from a given raw node body. Used both for the top-level
/// root and for inline (embedded) child nodes during descent.
fn walk_node<'a>(
    nodes: &'a HashMap<[u8; 32], Vec<u8>>,
    raw: &'a [u8],
    mut remaining: Vec<u8>,
) -> Result<Lookup<'a>> {
    let (item, _) = Rlp::decode(raw)?;
    let items = item.as_list()?;

    if items.len() == 17 {
        if remaining.is_empty() {
            let v = items[16].as_bytes()?;
            return Ok(if v.is_empty() { Lookup::Absent } else { Lookup::Found(v) });
        }
        let n = remaining.remove(0);
        return follow_child(nodes, &items[n as usize], remaining);
    }

    if items.len() == 2 {
        let path = items[0].as_bytes()?;
        let (path_nibs, is_leaf) = hp_decode(path);
        if is_leaf {
            if path_nibs == remaining {
                return Ok(Lookup::Found(items[1].as_bytes()?));
            }
            return Ok(Lookup::Absent);
        }
        // Extension
        if remaining.len() < path_nibs.len() || remaining[..path_nibs.len()] != path_nibs[..] {
            return Ok(Lookup::Absent);
        }
        remaining.drain(..path_nibs.len());
        return follow_child(nodes, &items[1], remaining);
    }

    Err(anyhow!("MPT: unexpected node shape (items={})", items.len()))
}

fn follow_child<'a>(
    nodes: &'a HashMap<[u8; 32], Vec<u8>>,
    child: &Rlp<'a>,
    remaining: Vec<u8>,
) -> Result<Lookup<'a>> {
    match child {
        Rlp::Bytes(b) if b.is_empty() => Ok(Lookup::Absent),
        Rlp::Bytes(b) if b.len() == 32 => {
            let h = <[u8; 32]>::try_from(*b).unwrap();
            match nodes.get(&h) {
                Some(raw) => walk_node(nodes, raw, remaining),
                None => Ok(Lookup::NotInWitness),
            }
        }
        // Inline child: a full RLP-encoded node embedded directly because its
        // total size is < 32 bytes. Walk it in place.
        Rlp::List(_) => {
            // RLP-encode the inline list bytes are still in the parent's
            // backing slice — but we only have the decoded Rlp here. Easiest:
            // re-encode the slice by finding it. Instead, encode-on-the-fly.
            let buf = encode(child);
            walk_node(nodes, leak(buf), remaining)
        }
        Rlp::Bytes(_) => Err(anyhow!("MPT: child bytes wrong length")),
    }
}

/// Minimal RLP encoder — only used to materialise inline children we
/// already have as a decoded `Rlp::List`. We never write trees from
/// scratch so this stays small.
fn encode(item: &Rlp<'_>) -> Vec<u8> {
    match item {
        Rlp::Bytes(b) => encode_bytes(b),
        Rlp::List(items) => {
            let mut payload = Vec::new();
            for it in items {
                payload.extend_from_slice(&encode(it));
            }
            let mut out = Vec::with_capacity(payload.len() + 9);
            if payload.len() < 56 {
                out.push(0xc0 + payload.len() as u8);
            } else {
                let len_bytes = be_bytes(payload.len() as u64);
                out.push(0xf7 + len_bytes.len() as u8);
                out.extend_from_slice(&len_bytes);
            }
            out.extend_from_slice(&payload);
            out
        }
    }
}

fn encode_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut out = Vec::with_capacity(b.len() + 9);
    if b.len() < 56 {
        out.push(0x80 + b.len() as u8);
    } else {
        let len_bytes = be_bytes(b.len() as u64);
        out.push(0xb7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(b);
    out
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

fn leak(v: Vec<u8>) -> &'static [u8] {
    Box::leak(v.into_boxed_slice())
}

/// Decode an Ethereum account leaf value: `RLP([nonce, balance, storageRoot, codeHash])`.
/// Returns `storageRoot`.
pub fn account_storage_root(value: &[u8]) -> Result<[u8; 32]> {
    let (item, _) = Rlp::decode(value)?;
    let fields = item.as_list()?;
    if fields.len() != 4 {
        return Err(anyhow!("account leaf: expected 4 fields, got {}", fields.len()));
    }
    let root = fields[2].as_bytes()?;
    if root.len() != 32 {
        return Err(anyhow!("account leaf: storageRoot is {} bytes, want 32", root.len()));
    }
    Ok(<[u8; 32]>::try_from(root).unwrap())
}

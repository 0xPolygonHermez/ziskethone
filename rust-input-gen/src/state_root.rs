//! StateRoot trie-hint stream encoder — **witness-only**.
//!
//! Transcribes the pre-state MPT exactly as `debug_executionWitness`
//! reveals it (state nodes keyed by hash + `keys` preimages), into the
//! opcode stream documented in `BINARY_FORMAT.md` §7, consumed by
//! `cpp-guest/src/state_root.cpp`.
//!
//! There is no longer any prestate/diff targeting: every node the witness
//! reveals is emitted (`Op::Branch` for branches, an `Op::Branch` chain for
//! revealed extensions, `Op::Leaf`/`Op::PhantomLeaf` for leaves), and a
//! subtree the witness only references by hash becomes `Op::Hash` /
//! `Op::ExtensionHash`. Keys CREATED during the block are NOT pre-emitted —
//! the guest inserts them into the revealed structure during the new-root
//! pass. Leaf values come straight from the witness leaf RLP.

use std::collections::HashMap;

use alloy::primitives::{Address, Bytes, B256, U256};
use anyhow::{bail, Context, Result};

use crate::mpt::{self, hp_decode, keccak256, Rlp};
use crate::writer::Writer;

/// Stream opcode tags, matching the `Op` enum in
/// `cpp-guest/src/state_root.cpp`.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Empty = 0,
    Hash = 1,
    ExtensionHash = 2,
    Leaf = 3,
    Branch = 4,
    PhantomLeaf = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeKind {
    State,
    Storage,
}

/// keccak256(rlp("")) — the root of an empty trie. A child referencing it is
/// an EMPTY subtree (it has no node), so it is emitted as `Op::Empty` rather
/// than an opaque `Op::Hash` — this lets the guest INSERT into it (e.g. the
/// first storage slot of an account whose block-start storage is empty, like
/// the Pectra system contracts on their first write).
const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// A reference to a child subtree, as it appears inside a parent node.
enum ChildRef {
    Empty,
    Hash([u8; 32]),
    Inline(Vec<u8>),
}

/// Witness-driven emitter. Holds the node store + preimage map and
/// accumulates the opcode stream and the leaf counts (which become the
/// section header).
struct Encoder<'a> {
    nodes: &'a HashMap<[u8; 32], Vec<u8>>,
    /// keccak(preimage) → preimage (addresses for the state trie, slots for
    /// storage tries). Only accessed keys have a preimage; keyless siblings
    /// stay `Op::PhantomLeaf`.
    preimages: &'a HashMap<[u8; 32], Vec<u8>>,
    out: Vec<u8>,
    n_accounts: u64,
    n_storages: u64,
}

pub fn write(
    w: &mut Writer,
    parent_state_root: B256,
    witness_nodes: &[Bytes],
    witness_keys: &[Bytes],
) -> Result<()> {
    let mut nodes: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(witness_nodes.len());
    for raw in witness_nodes {
        if raw.len() < 32 {
            continue;
        }
        nodes.insert(keccak256(raw), raw.to_vec());
    }
    let mut preimages: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(witness_keys.len());
    for key in witness_keys {
        preimages.insert(keccak256(key), key.to_vec());
    }

    let mut enc = Encoder {
        nodes: &nodes,
        preimages: &preimages,
        out: Vec::new(),
        n_accounts: 0,
        n_storages: 0,
    };
    enc.emit_child(&[], ChildRef::Hash(parent_state_root.0), TreeKind::State)?;

    // Header (before the opcode stream): three u64 counts. numberOfNodes is
    // a conservative upper bound (every node is >= one 8-byte opcode word);
    // numberOfAccounts/numberOfStorages are the witness leaf counts.
    w.u64_le((enc.out.len() / 8) as u64);
    w.u64_le(enc.n_accounts);
    w.u64_le(enc.n_storages);
    for byte in &enc.out {
        w.u8(*byte);
    }
    w.assert_aligned();
    Ok(())
}

// ===== helpers ==============================================================

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_op(out: &mut Vec<u8>, op: Op) {
    put_u64(out, op as u64);
}

/// State `Op::Leaf` payload (after the suffix-nibble prefix): the PLAINTEXT
/// key first — address(20) pad(4) — so the guest keys its runtime table by
/// plaintext (fast hot path), then the value fields balance(u256be,32)
/// nonce(u64,LE) code_hash(32). The suffix nibbles carry the trie key hash;
/// the guest binds the two via keccak(address) == pack(walked ++ suffix).
fn put_state_leaf_payload(
    out: &mut Vec<u8>,
    addr: &Address,
    balance: &U256,
    nonce: u64,
    code_hash: &B256,
) {
    out.extend_from_slice(addr.as_slice()); // 20
    out.extend_from_slice(&[0u8; 4]); // pad to 24
    out.extend_from_slice(&balance.to_be_bytes::<32>()); // 32
    put_u64(out, nonce); // 8
    out.extend_from_slice(code_hash.as_slice()); // 32
}

/// Storage `Op::Leaf` payload (after the suffix-nibble prefix): the PLAINTEXT
/// slot position(32) then value(32). Position keys the runtime table.
fn put_storage_leaf_payload(out: &mut Vec<u8>, position: &B256, value: &B256) {
    out.extend_from_slice(position.as_slice()); // 32
    out.extend_from_slice(value.as_slice()); // 32
}

/// Pack a full 64-nibble trie path into the 32-byte key hash.
fn nibbles_to_bytes(nibs: &[u8]) -> Result<[u8; 32]> {
    if nibs.len() != 64 {
        bail!("leaf path must be 64 nibbles, got {}", nibs.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nibs[2 * i] << 4) | nibs[2 * i + 1];
    }
    Ok(out)
}

/// Interpret one element of a branch (or an extension's child) as a child
/// reference: an empty string, a 32-byte hash, or a small inline node.
fn child_ref(item: &Rlp<'_>) -> Result<ChildRef> {
    match item {
        Rlp::Bytes([]) => Ok(ChildRef::Empty),
        Rlp::Bytes(b) if b.len() == 32 => Ok(ChildRef::Hash(<[u8; 32]>::try_from(*b).unwrap())),
        Rlp::List(_) => Ok(ChildRef::Inline(mpt::rlp_encode(item))),
        Rlp::Bytes(b) => bail!("MPT child has unexpected length {}", b.len()),
    }
}

impl<'a> Encoder<'a> {
    /// Emit the subtree at `child`, with `walked` nibbles consumed so far.
    fn emit_child(&mut self, walked: &[u8], child: ChildRef, kind: TreeKind) -> Result<()> {
        match child {
            ChildRef::Empty => put_op(&mut self.out, Op::Empty),
            ChildRef::Inline(bytes) => self.emit_node(walked, &bytes, kind)?,
            ChildRef::Hash(h) if h == EMPTY_TRIE_ROOT => {
                // Empty subtree (no node) — emit as Empty so the guest can
                // insert created keys into it.
                put_op(&mut self.out, Op::Empty);
            }
            ChildRef::Hash(h) => match self.nodes.get(&h) {
                Some(raw) => {
                    let raw = raw.clone();
                    self.emit_node(walked, &raw, kind)?;
                }
                None => {
                    // Subtree the witness only references by hash → opaque.
                    put_op(&mut self.out, Op::Hash);
                    self.out.extend_from_slice(&h);
                }
            },
        }
        Ok(())
    }

    /// Emit a fully-revealed node given its RLP.
    fn emit_node(&mut self, walked: &[u8], node_rlp: &[u8], kind: TreeKind) -> Result<()> {
        let (item, _) = Rlp::decode(node_rlp)?;
        let items = item.as_list()?;
        match items.len() {
            17 => {
                put_op(&mut self.out, Op::Branch);
                for (k, item) in items.iter().enumerate().take(16) {
                    let cr = child_ref(item)?;
                    let mut w = walked.to_vec();
                    w.push(k as u8);
                    self.emit_child(&w, cr, kind)?;
                }
                // items[16] (the branch value) is always empty for the
                // state / storage tries — ignored.
            }
            2 => {
                let (nibs, is_leaf) = hp_decode(items[0].as_bytes()?);
                if is_leaf {
                    self.emit_leaf(walked, &nibs, items[1].as_bytes()?, kind)?;
                } else {
                    self.emit_extension(walked, &nibs, &items[1], kind)?;
                }
            }
            n => bail!("MPT: unexpected node shape (items={})", n),
        }
        Ok(())
    }

    /// Emit an extension as a chain of single-child branches (one per nibble);
    /// the guest's `reduce_branch` folds them back into an extension at hash
    /// time. The chain terminates in whatever the extension's child resolves
    /// to via `emit_child`: a revealed subtree, or — when the witness only
    /// references the child by hash — an `Op::Hash`.
    ///
    /// We deliberately do NOT emit a single opaque `Op::ExtensionHash` even
    /// for an unrevealed child. A bare `ExtensionHash` is unsplittable: when
    /// the new-root pass inserts a CREATED key whose path diverges *inside*
    /// the extension's nibbles, the guest can't break the extension apart and
    /// aborts ("insert into an unrevealed (Hash) subtree — witness
    /// incomplete"). reth's `debug_executionWitness` collapses the untouched
    /// remainder of a storage trie to hashes, so this is common for created
    /// storage slots, and the child node simply isn't fetchable offline (an
    /// `eth_getProof` at the parent block falls outside the node's proof
    /// window for non-recent blocks).
    ///
    /// Emitting the branch-chain instead exposes every nibble of the
    /// extension as a single-child branch the guest CAN split — the created
    /// key lands in an empty slot at the divergence branch, and the original
    /// (still-hashed) child stays an `Op::Hash` sibling. `reduce_branch` folds
    /// a single Hash child back into `ExtR{[nibble], child_hash}`, so the
    /// reconstructed root is byte-identical to the `ExtensionHash` encoding.
    /// (`Op::ExtensionHash` remains supported by the guest for back-compat;
    /// the writer no longer produces it.)
    fn emit_extension(
        &mut self,
        walked: &[u8],
        nibs: &[u8],
        child: &Rlp<'_>,
        kind: TreeKind,
    ) -> Result<()> {
        let cr = child_ref(child)?;
        self.emit_ext_chain(walked, nibs, cr, kind)
    }

    fn emit_ext_chain(
        &mut self,
        walked: &[u8],
        nibs: &[u8],
        child: ChildRef,
        kind: TreeKind,
    ) -> Result<()> {
        if nibs.is_empty() {
            return self.emit_child(walked, child, kind);
        }
        // One single-child branch level: empties before `head`, the
        // continuation at `head`, empties after.
        put_op(&mut self.out, Op::Branch);
        let head = nibs[0];
        for _ in 0..head {
            put_op(&mut self.out, Op::Empty);
        }
        let mut w = walked.to_vec();
        w.push(head);
        self.emit_ext_chain(&w, &nibs[1..], child, kind)?;
        for _ in (head + 1)..16 {
            put_op(&mut self.out, Op::Empty);
        }
        Ok(())
    }

    /// Emit a leaf at position `walked` whose hex-prefix tail is `leaf_nibs`
    /// and whose value field is `value`. If the key's preimage is known →
    /// `Op::Leaf` (+ values decoded from the witness RLP; state leaves then
    /// recurse into their storage subtree). Otherwise → `Op::PhantomLeaf`.
    fn emit_leaf(
        &mut self,
        walked: &[u8],
        leaf_nibs: &[u8],
        value: &[u8],
        kind: TreeKind,
    ) -> Result<()> {
        // With a preimage → Op::Leaf carrying suffix nibbles + plaintext key +
        // value (the guest keys runtime tables by plaintext). Keyless siblings
        // → Op::PhantomLeaf (trie-only, never entered into the tables).
        let mut full = walked.to_vec();
        full.extend_from_slice(leaf_nibs);
        let key_hash = nibbles_to_bytes(&full)?;

        let preimage = self.preimages.get(&key_hash).cloned();
        match preimage {
            Some(pre) => {
                put_op(&mut self.out, Op::Leaf);
                // suffix nibbles: count + one u64 per nibble.
                put_u64(&mut self.out, leaf_nibs.len() as u64);
                for &n in leaf_nibs {
                    put_u64(&mut self.out, n as u64);
                }
                match kind {
                    TreeKind::State => {
                        self.n_accounts += 1;
                        let (nonce, balance_be, storage_root, code_hash) =
                            mpt::decode_account(value).context("state leaf RLP")?;
                        let addr = Address::from_slice(&pre);
                        put_state_leaf_payload(
                            &mut self.out,
                            &addr,
                            &U256::from_be_bytes(balance_be),
                            nonce,
                            &B256::from(code_hash),
                        );
                        // Recurse into the per-account storage subtree.
                        self.emit_child(&[], ChildRef::Hash(storage_root), TreeKind::Storage)?;
                    }
                    TreeKind::Storage => {
                        self.n_storages += 1;
                        let slot = B256::from_slice(&pre);
                        let val = mpt::decode_storage_value(value).context("storage leaf RLP")?;
                        put_storage_leaf_payload(&mut self.out, &slot, &B256::from(val));
                    }
                }
            }
            None => {
                // Keyless sibling (no preimage in witness.keys) → carry it
                // inline with its remaining path + raw value field.
                put_op(&mut self.out, Op::PhantomLeaf);
                put_u64(&mut self.out, leaf_nibs.len() as u64);
                for &n in leaf_nibs {
                    put_u64(&mut self.out, n as u64);
                }
                put_u64(&mut self.out, value.len() as u64);
                self.out.extend_from_slice(value);
                let pad = (8 - (value.len() % 8)) % 8;
                for _ in 0..pad {
                    self.out.push(0);
                }
            }
        }
        Ok(())
    }
}

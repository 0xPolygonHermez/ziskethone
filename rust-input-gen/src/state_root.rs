//! StateRoot trie-hint stream encoder — **witness-only**.
//!
//! Transcribes the pre-state MPT exactly as `debug_executionWitness`
//! reveals it (state nodes keyed by hash + `keys` preimages), into the
//! opcode stream documented in `BINARY_FORMAT.md` §7, consumed by
//! `cpp-guest/src/state_root.cpp`.
//!
//! Every node the witness reveals is emitted (`Op::Branch` for branches, an
//! `Op::Branch` chain for revealed extensions, `Op::Leaf`/`Op::PhantomLeaf`
//! for leaves), and a subtree the witness only references by hash becomes
//! `Op::Hash`. Leaf values come straight from the witness leaf RLP.
//!
//! Every key the block accesses must be a leaf, so the guest can halt on any
//! other access: an accessed key that doesn't exist is placed as a leaf with
//! empty values where it would sit in the trie (splitting a diverging leaf
//! into a branch when needed). An empty leaf hashes as Empty and the branch
//! folds back, so the old root is unchanged and the guest's parent-root check
//! proves the absence. Keys created during the block are accessed keys too,
//! so they are already in place for the new-root pass.

use std::collections::{BTreeMap, BTreeSet};

use alloy::primitives::map::B256Map;
use alloy::primitives::{Address, Bytes, B256, U256};
use anyhow::{bail, Context, Result};
use rayon::prelude::*;
use tracing::info;

use crate::mpt::{self, hp_decode, keccak256, nibbles_of, Rlp};
use crate::sections::EMPTY_CODE_HASH;
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

/// The revealed pre-state trie, decoded into memory so absent keys can be
/// inserted before it is emitted. Revealed extensions are already expanded
/// into chains of single-child branches (see `Decoder::ext_chain`).
enum Node {
    Empty,
    /// A subtree the witness only references by hash.
    Hash([u8; 32]),
    Branch(Box<[Node; 16]>),
    /// A leaf; `path` is its remaining nibbles below the parent.
    Leaf { path: Vec<u8>, data: LeafData },
}

enum LeafData {
    Account {
        addr: Address,
        balance: U256,
        nonce: u64,
        code_hash: B256,
        storage: Box<Node>,
    },
    Slot { slot: B256, value: B256 },
    /// A leaf whose key has no preimage: carried as its raw value field.
    Phantom { value: Vec<u8> },
}

/// Accounts and slots the block accesses, by plaintext key. Every one of
/// them must be a leaf in the emitted tree: an existing key with its
/// block-start values, a key that doesn't exist as a leaf with empty values.
/// The guest halts on any access to a key that isn't a leaf.
pub type Accessed = BTreeMap<Address, BTreeSet<B256>>;

pub fn write(
    w: &mut Writer,
    parent_state_root: B256,
    witness_nodes: &[Bytes],
    witness_keys: &[Bytes],
    accessed: &Accessed,
) -> Result<()> {
    // Hashing every witness node is most of this function's time and each
    // hash is independent, so spread it over the cores.
    let hashed: Vec<(B256, &[u8])> = witness_nodes
        .par_iter()
        .filter(|raw| raw.len() >= 32)
        .map(|raw| (B256::from(keccak256(raw)), raw.as_ref()))
        .collect();
    let mut nodes: B256Map<&[u8]> =
        B256Map::with_capacity_and_hasher(hashed.len(), Default::default());
    nodes.extend(hashed);

    // Preimages: the witness keys plus every accessed key (reth's keys omit
    // accounts that don't exist).
    let mut preimages: B256Map<Vec<u8>> =
        B256Map::with_capacity_and_hasher(witness_keys.len(), Default::default());
    for key in witness_keys {
        preimages.insert(B256::from(keccak256(key)), key.to_vec());
    }
    for (addr, slots) in accessed {
        preimages.insert(B256::from(keccak256(addr.as_slice())), addr.to_vec());
        for slot in slots {
            preimages.insert(B256::from(keccak256(slot.as_slice())), slot.to_vec());
        }
    }

    let dec = Decoder { nodes: &nodes, preimages: &preimages };
    let mut root = dec.child(&[], ChildRef::Hash(parent_state_root.0), TreeKind::State)?;

    // Place every accessed key that isn't a leaf yet as an empty leaf. A key
    // whose path runs into an unrevealed subtree can't be placed; if the
    // guest needs it, it halts.
    let mut placed = (0usize, 0usize);
    let mut unrevealed = (0usize, 0usize);
    for (addr, slots) in accessed {
        let ah = keccak256(addr.as_slice());
        let leaf = LeafData::Account {
            addr: *addr,
            balance: U256::ZERO,
            nonce: 0,
            code_hash: EMPTY_CODE_HASH,
            storage: Box::new(Node::Empty),
        };
        match insert(&mut root, &nibbles_of(&ah), leaf)? {
            Insert::Placed => placed.0 += 1,
            Insert::Exists => {}
            Insert::Unrevealed => {
                unrevealed.0 += 1;
                continue;
            }
        }
        if slots.is_empty() {
            continue;
        }
        let Some(storage) = find_account_storage(&mut root, &nibbles_of(&ah)) else {
            continue;
        };
        for slot in slots {
            let sh = keccak256(slot.as_slice());
            let leaf = LeafData::Slot { slot: *slot, value: B256::ZERO };
            match insert(storage, &nibbles_of(&sh), leaf)? {
                Insert::Placed => placed.1 += 1,
                Insert::Exists => {}
                Insert::Unrevealed => unrevealed.1 += 1,
            }
        }
    }
    info!(
        absent_accounts = placed.0,
        absent_slots = placed.1,
        unrevealed_accounts = unrevealed.0,
        unrevealed_slots = unrevealed.1,
        "placed absent keys as empty leaves",
    );

    // Rows in walk order, for the sorted-order links.
    let mut rows = Rows::default();
    collect_rows(&root, &mut rows, None);
    let links = Links::new(&rows);

    let mut enc = Encoder {
        out: Vec::new(),
        n_nodes: 0,
        links: &links,
        next_account: 0,
        next_storage: 0,
    };
    enc.emit(&root, false);

    // Header (before the opcode stream): node count (a ceiling), the exact
    // account / storage row counts, and the head of the sorted-order links.
    w.u64_le(enc.n_nodes);
    w.u64_le(rows.accounts.len() as u64);
    w.u64_le(rows.n_storages as u64);
    w.u64_le(links.first_account);
    w.bytes(&enc.out);
    w.assert_aligned();
    Ok(())
}

/// Ends a sorted-order list.
const NO_LINK: u64 = u64::MAX;

// ===== helpers ==============================================================

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_op(out: &mut Vec<u8>, op: Op) {
    put_u64(out, op as u64);
}

/// Two bits per child in the word after `Op::Branch`; a tagged Empty child
/// costs no bytes and a tagged Hash child only its 32.
const TAG_EMPTY: u64 = 0;
const TAG_HASH: u64 = 1;
const TAG_NODE: u64 = 2;

/// Count, then two nibbles per byte, padded to 8 to keep the guest's cursor
/// aligned.
fn put_nibbles(out: &mut Vec<u8>, nibs: &[u8]) {
    put_u64(out, nibs.len() as u64);
    let start = out.len();
    for pair in nibs.chunks(2) {
        let hi = pair[0] << 4;
        out.push(if pair.len() == 2 { hi | (pair[1] & 0x0f) } else { hi });
    }
    let pad = (8 - (out.len() - start) % 8) % 8;
    out.extend(std::iter::repeat(0u8).take(pad));
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


// ===== decode ===============================================================

struct Decoder<'a> {
    nodes: &'a B256Map<&'a [u8]>,
    /// keccak(preimage) → preimage. Leaves without one stay `Phantom`.
    preimages: &'a B256Map<Vec<u8>>,
}

impl Decoder<'_> {
    fn child(&self, walked: &[u8], child: ChildRef, kind: TreeKind) -> Result<Node> {
        match child {
            ChildRef::Empty => Ok(Node::Empty),
            ChildRef::Inline(bytes) => self.node(walked, &bytes, kind),
            // An empty subtree has no node — Empty, so keys can be placed in it.
            ChildRef::Hash(h) if h == EMPTY_TRIE_ROOT => Ok(Node::Empty),
            ChildRef::Hash(h) => match self.nodes.get(&B256::from(h)).copied() {
                Some(raw) => self.node(walked, raw, kind),
                None => Ok(Node::Hash(h)),
            },
        }
    }

    fn node(&self, walked: &[u8], node_rlp: &[u8], kind: TreeKind) -> Result<Node> {
        let (item, _) = Rlp::decode(node_rlp)?;
        let items = item.as_list()?;
        match items.len() {
            17 => {
                let mut children: [Node; 16] = std::array::from_fn(|_| Node::Empty);
                let mut w = Vec::with_capacity(walked.len() + 1);
                w.extend_from_slice(walked);
                w.push(0);
                for (k, item) in items.iter().enumerate().take(16) {
                    *w.last_mut().unwrap() = k as u8;
                    children[k] = self.child(&w, child_ref(item)?, kind)?;
                }
                // items[16] (the branch value) is always empty for the state /
                // storage tries — ignored.
                Ok(Node::Branch(Box::new(children)))
            }
            2 => {
                let (nibs, is_leaf) = hp_decode(items[0].as_bytes()?);
                if is_leaf {
                    self.leaf(walked, nibs, items[1].as_bytes()?, kind)
                } else {
                    self.ext_chain(walked, &nibs, child_ref(&items[1])?, kind)
                }
            }
            n => bail!("MPT: unexpected node shape (items={})", n),
        }
    }

    /// An extension as a chain of single-child branches, one per nibble; the
    /// guest's `reduce_branch` folds them back into an extension at hash time.
    /// The chain ends in whatever the extension's child resolves to — a
    /// revealed subtree, or an `Op::Hash` when the witness only references it.
    ///
    /// We deliberately never emit an opaque `Op::ExtensionHash`: it can't be
    /// split, so a key whose path diverges inside the extension's nibbles
    /// (an absent key placed here, or a created key) couldn't be placed. The
    /// chain exposes every nibble as a branch with a free slot at the
    /// divergence, and the still-hashed child stays an `Op::Hash` sibling.
    /// `reduce_branch` folds a single Hash child back into
    /// `ExtR{[nibble], child_hash}`, so the root is byte-identical.
    fn ext_chain(&self, walked: &[u8], nibs: &[u8], child: ChildRef, kind: TreeKind) -> Result<Node> {
        if nibs.is_empty() {
            bail!("MPT: extension with an empty nibble path");
        }
        let mut w = walked.to_vec();
        w.push(nibs[0]);
        let inner = if nibs.len() > 1 {
            self.ext_chain(&w, &nibs[1..], child, kind)?
        } else {
            self.child(&w, child, kind)?
        };
        Ok(single_child(nibs[0], inner))
    }

    /// A leaf at `walked` with hex-prefix tail `leaf_nibs`. With a preimage it
    /// is keyed (values decoded from the witness RLP; a state leaf also
    /// decodes its storage subtree); without one it stays `Phantom`.
    fn leaf(&self, walked: &[u8], leaf_nibs: Vec<u8>, value: &[u8], kind: TreeKind) -> Result<Node> {
        let mut full = walked.to_vec();
        full.extend_from_slice(&leaf_nibs);
        let key_hash = nibbles_to_bytes(&full)?;
        let data = match self.preimages.get(&B256::from(key_hash)) {
            None => LeafData::Phantom { value: value.to_vec() },
            Some(pre) => match kind {
                TreeKind::State => {
                    let (nonce, balance_be, storage_root, code_hash) =
                        mpt::decode_account(value).context("state leaf RLP")?;
                    let storage =
                        self.child(&[], ChildRef::Hash(storage_root), TreeKind::Storage)?;
                    LeafData::Account {
                        addr: Address::from_slice(pre),
                        balance: U256::from_be_bytes(balance_be),
                        nonce,
                        code_hash: B256::from(code_hash),
                        storage: Box::new(storage),
                    }
                }
                TreeKind::Storage => {
                    let val = mpt::decode_storage_value(value).context("storage leaf RLP")?;
                    LeafData::Slot { slot: B256::from_slice(pre), value: B256::from(val) }
                }
            },
        };
        Ok(Node::Leaf { path: leaf_nibs, data })
    }
}

fn single_child(nibble: u8, child: Node) -> Node {
    let mut children: [Node; 16] = std::array::from_fn(|_| Node::Empty);
    children[nibble as usize] = child;
    Node::Branch(Box::new(children))
}

// ===== absent keys ==========================================================

enum Insert {
    Placed,
    Exists,
    /// The key's path runs into a `Hash` subtree.
    Unrevealed,
}

/// Place `data` as a leaf at key path `rest` under `node`, the way the guest's
/// `insert_into` / `split_leaf` would: in an Empty slot, or by splitting a
/// leaf whose path diverges into a branch (with a single-child chain for the
/// shared prefix). An empty-valued leaf hashes as Empty and the branches fold
/// back, so the old root is unchanged and the guest's parent-root check
/// proves the key's absence.
fn insert(node: &mut Node, rest: &[u8], data: LeafData) -> Result<Insert> {
    match node {
        Node::Empty => {
            *node = Node::Leaf { path: rest.to_vec(), data };
            Ok(Insert::Placed)
        }
        Node::Hash(_) => Ok(Insert::Unrevealed),
        Node::Branch(children) => {
            if rest.is_empty() {
                bail!("MPT: key path ended at a branch");
            }
            insert(&mut children[rest[0] as usize], &rest[1..], data)
        }
        Node::Leaf { path, .. } => {
            if path.as_slice() == rest {
                return Ok(Insert::Exists);
            }
            if path.len() != rest.len() {
                bail!("MPT: leaf path length mismatch");
            }
            let c = path.iter().zip(rest).take_while(|(a, b)| a == b).count();
            let Node::Leaf { path: old_path, data: old_data } =
                std::mem::replace(node, Node::Empty)
            else {
                unreachable!()
            };
            let mut children: [Node; 16] = std::array::from_fn(|_| Node::Empty);
            children[old_path[c] as usize] =
                Node::Leaf { path: old_path[c + 1..].to_vec(), data: old_data };
            children[rest[c] as usize] = Node::Leaf { path: rest[c + 1..].to_vec(), data };
            let mut n = Node::Branch(Box::new(children));
            for &nib in rest[..c].iter().rev() {
                n = single_child(nib, n);
            }
            *node = n;
            Ok(Insert::Placed)
        }
    }
}

/// The storage subtree of the keyed account leaf at key path `rest`.
fn find_account_storage<'n>(node: &'n mut Node, rest: &[u8]) -> Option<&'n mut Node> {
    match node {
        Node::Branch(children) if !rest.is_empty() => {
            find_account_storage(&mut children[rest[0] as usize], &rest[1..])
        }
        Node::Leaf { path, data: LeafData::Account { storage, .. } } if path.as_slice() == rest => {
            Some(storage)
        }
        _ => None,
    }
}

// ===== rows and links =======================================================

/// The keyed rows in walk order (the guest's row indices): accounts, and the
/// storage rows of each account, numbered globally in walk order.
#[derive(Default)]
struct Rows {
    accounts: Vec<(Address, Vec<(B256, u64)>)>,
    n_storages: u64,
}

fn collect_rows(node: &Node, rows: &mut Rows, owner: Option<usize>) {
    match node {
        Node::Empty | Node::Hash(_) => {}
        Node::Branch(children) => {
            for c in children.iter() {
                collect_rows(c, rows, owner);
            }
        }
        Node::Leaf { data, .. } => match data {
            LeafData::Account { addr, storage, .. } => {
                rows.accounts.push((*addr, Vec::new()));
                let me = rows.accounts.len() - 1;
                collect_rows(storage, rows, Some(me));
            }
            LeafData::Slot { slot, .. } => {
                let idx = rows.n_storages;
                rows.n_storages += 1;
                rows.accounts[owner.expect("storage leaf outside an account")].1.push((*slot, idx));
            }
            LeafData::Phantom { .. } => {}
        },
    }
}

/// Sorted-order links: accounts by address, each account's slots by
/// position. Indexed by row index.
struct Links {
    first_account: u64,
    next_account: Vec<u64>,
    first_storage: Vec<u64>,
    next_storage: Vec<u64>,
}

impl Links {
    fn new(rows: &Rows) -> Self {
        let n = rows.accounts.len();
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by(|&a, &b| rows.accounts[a].0.cmp(&rows.accounts[b].0));
        let mut next_account = vec![NO_LINK; n];
        for pair in order.windows(2) {
            next_account[pair[0]] = pair[1] as u64;
        }
        let first_account = order.first().map_or(NO_LINK, |&i| i as u64);

        let mut first_storage = vec![NO_LINK; n];
        let mut next_storage = vec![NO_LINK; rows.n_storages as usize];
        for (i, (_, slots)) in rows.accounts.iter().enumerate() {
            let mut sorted = slots.clone();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            for pair in sorted.windows(2) {
                next_storage[pair[0].1 as usize] = pair[1].1;
            }
            first_storage[i] = sorted.first().map_or(NO_LINK, |s| s.1);
        }
        Links { first_account, next_account, first_storage, next_storage }
    }
}

// ===== emit =================================================================

struct Encoder<'a> {
    out: Vec<u8>,
    /// Node count for the header, which the guest uses as a ceiling (any
    /// value ≥ the true count is safe). Counts every child slot of a branch.
    n_nodes: u64,
    links: &'a Links,
    next_account: usize,
    next_storage: usize,
}

fn tag_of(node: &Node) -> u64 {
    match node {
        Node::Empty => TAG_EMPTY,
        Node::Hash(_) => TAG_HASH,
        _ => TAG_NODE,
    }
}

impl Encoder<'_> {
    /// Emit `node`. Under a branch (`tagged`) an Empty child writes nothing
    /// and a Hash child only its 32 bytes — the branch's tag word says which.
    fn emit(&mut self, node: &Node, tagged: bool) {
        self.n_nodes += 1;
        match node {
            Node::Empty => {
                if !tagged {
                    put_op(&mut self.out, Op::Empty);
                }
            }
            Node::Hash(h) => {
                if !tagged {
                    put_op(&mut self.out, Op::Hash);
                }
                self.out.extend_from_slice(h);
            }
            Node::Branch(children) => {
                put_op(&mut self.out, Op::Branch);
                let mut tags: u64 = 0;
                for (k, c) in children.iter().enumerate() {
                    tags |= tag_of(c) << (2 * k);
                }
                put_u64(&mut self.out, tags);
                for c in children.iter() {
                    self.emit(c, true);
                }
            }
            Node::Leaf { path, data } => match data {
                LeafData::Account { addr, balance, nonce, code_hash, storage } => {
                    put_op(&mut self.out, Op::Leaf);
                    put_nibbles(&mut self.out, path);
                    put_state_leaf_payload(&mut self.out, addr, balance, *nonce, code_hash);
                    let i = self.next_account;
                    self.next_account += 1;
                    put_u64(&mut self.out, self.links.next_account[i]);
                    put_u64(&mut self.out, self.links.first_storage[i]);
                    // The per-account storage subtree follows.
                    self.emit(storage, false);
                }
                LeafData::Slot { slot, value } => {
                    put_op(&mut self.out, Op::Leaf);
                    put_nibbles(&mut self.out, path);
                    put_storage_leaf_payload(&mut self.out, slot, value);
                    let i = self.next_storage;
                    self.next_storage += 1;
                    put_u64(&mut self.out, self.links.next_storage[i]);
                }
                LeafData::Phantom { value } => {
                    // Keyless sibling — its remaining path + raw value field.
                    put_op(&mut self.out, Op::PhantomLeaf);
                    put_nibbles(&mut self.out, path);
                    put_u64(&mut self.out, value.len() as u64);
                    self.out.extend_from_slice(value);
                    let pad = (8 - (value.len() % 8)) % 8;
                    self.out.extend(std::iter::repeat(0u8).take(pad));
                }
            },
        }
    }
}

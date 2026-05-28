//! StateRoot trie-hint stream encoder (Phase 5).
//!
//! Walks the partial MPT reconstructed from `debug_executionWitness`
//! and emits the opcode stream documented in `BINARY_FORMAT.md` §7,
//! consumed by `cpp-guest/src/state_root.cpp::walk_node`.
//!
//! Algorithm (matches the design in the chat transcript):
//!
//! 1. Walk the trie top-down with the set of touched keys (targets).
//! 2. At each MPT node:
//!    * **0 targets** → the subtree is untouched; emit `Op::Hash` with
//!      the subtree's root hash. (`Op::Empty` for the empty-trie root.)
//!    * **1 target** → emit `Op::Leaf` with that target's index. The
//!      cpp-guest builds the leaf with `nibbles_walked` automatically.
//!      For state-trie leaves, recurse into the per-account storage
//!      subtree with the touched slot targets for that account.
//!    * **≥2 targets** → descend:
//!      * Branch node → 16-way bucket by next nibble; recurse on each.
//!      * Extension or leaf node → "expand" the path nibble by nibble.
//!        At each level we emit a synthetic `NodeRW`/`NodeR`; targets
//!        whose next nibble matches the path nibble fall into the
//!        continuation slot, others become divergent insertions in
//!        their own slots. The cpp-guest's `reduce_branch` folds
//!        consecutive single-child branches back into an extension,
//!        so the reconstructed trie matches byte-for-byte.
//! 3. When divergence happens within an extension/leaf, the
//!    continuation slot leads to the rest of the original path plus
//!    the original child. If no target follows the continuation we
//!    emit `Op::Hash` with the **recomputed** sub-node hash (the
//!    leaf's path is shorter at the new depth, so its hash is
//!    different from the original MPT node hash).

use std::collections::HashMap;

use alloy::primitives::{Address, Bytes, B256};
use anyhow::{anyhow, bail, Context, Result};
use sha3::{Digest, Keccak256};

use crate::mpt::{self, hp_decode, keccak256, Rlp};
use crate::rpc::PrestateDiff;
use crate::touchset::TouchSet;
use crate::writer::Writer;

/// Stream opcode tags, matching the `Op` enum in
/// `cpp-guest/src/state_root.cpp`.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Empty         = 0,
    Hash          = 1,
    ExtensionHash = 2,
    Leaf          = 3,
    NodeRw        = 4,
    NodeR         = 5,
    /// Fallback: untouched-sibling leaf re-positioned during a
    /// structural split when its keccak preimage is missing from
    /// `witness.keys` (so we can't look up an Accounts/Storages idx).
    /// Common path uses `Op::Leaf <idx>` instead, via the witness-
    /// driven enrichment in `enrich::enrich_state_leaves_from_witness`
    /// + `enrich_storage_slots_from_witness`. Payload: path nibbles
    /// + raw value bytes; cpp-guest's `PhantomLeafR` folds back
    /// through reduce_branch as the wrap collapses.
    PhantomLeaf   = 6,
}

pub fn write(
    w: &mut Writer,
    parent_state_root: B256,
    witness_nodes: &[Bytes],
    touch: &TouchSet,
    diff: &PrestateDiff,
) -> Result<()> {
    let mut nodes: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(witness_nodes.len());
    for raw in witness_nodes {
        if raw.len() < 32 {
            continue;
        }
        nodes.insert(keccak256(raw), raw.to_vec());
    }

    // Mark every touched account as a writer. The conservative
    // labelling forces the cpp-guest to recompute every leaf in the
    // new-root pass instead of replaying the old-pass NodeR cache —
    // necessary because some accounts mutate outside the tx execution
    // diff (withdrawal balance credits, EIP-7002 / 7251 system call
    // slot writes, etc.) and those mutations would otherwise be
    // dropped from the new root.
    let _ = diff;
    let mut state_targets: Vec<Target> = touch
        .addrs
        .iter()
        .enumerate()
        .map(|(idx, addr)| Target {
            key_hash: keccak256(addr.as_slice()),
            leaf_idx: idx,
            is_write: true,
        })
        .collect();
    state_targets.sort_by_key(|t| t.key_hash);

    let ctx = Ctx { nodes: &nodes, touch, diff };

    let mut out = Vec::new();
    walk(
        &mut out,
        &ctx,
        &[],
        &state_targets,
        SubtreeChild::HashRef(parent_state_root.0),
        TreeKind::State,
        None,
    )?;

    for byte in out {
        w.u8(byte);
    }
    w.assert_aligned();
    Ok(())
}

// ===== internal types ========================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeKind {
    State,
    Storage,
}

#[derive(Clone, Debug)]
struct Target {
    key_hash: [u8; 32],
    leaf_idx: usize,
    is_write: bool,
}

struct Ctx<'a> {
    nodes: &'a HashMap<[u8; 32], Vec<u8>>,
    touch: &'a TouchSet,
    diff:  &'a PrestateDiff,
}

#[derive(Clone, Copy)]
enum SubtreeChild<'a> {
    /// A by-hash subtree reference — look up in `Ctx::nodes`.
    HashRef([u8; 32]),
    /// An inline RLP subtree (< 32 B; embedded directly in parent slot).
    Inline(&'a [u8]),
    /// A slot we synthesized that has no MPT data (insertion site).
    Empty,
}

// ===== nibble / byte helpers =================================================

fn nibble_at(hash: &[u8; 32], i: usize) -> u8 {
    let b = hash[i / 2];
    if i % 2 == 0 { b >> 4 } else { b & 0x0f }
}

/// Wrap `inner` (a complete subtree stream) in N single-child synthetic
/// `NodeRW`/`NodeR` levels, one per nibble of `nibbles`. Each level
/// holds `inner` at slot `nibbles[i]` and `Op::Empty` at the other 15
/// slots. `has_write` picks NodeRW vs NodeR. The cpp-guest's
/// `reduce_branch` then folds the chain back into an `ExtR` with the
/// same nibbles + the original child.
fn wrap_with_extension(out: &mut Vec<u8>, inner: &mut Vec<u8>, nibbles: &[u8], has_write: bool) {
    if nibbles.is_empty() {
        out.append(inner);
        return;
    }
    let op = if has_write { Op::NodeRw } else { Op::NodeR };
    let mut current = std::mem::take(inner);
    for &nib in nibbles.iter().rev() {
        let mut wrapped = Vec::new();
        put_op(&mut wrapped, op);
        for k in 0..16u8 {
            if k == nib {
                wrapped.extend(&current);
            } else {
                emit_empty(&mut wrapped);
            }
        }
        current = wrapped;
    }
    out.extend_from_slice(&current);
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_op(out: &mut Vec<u8>, op: Op) {
    put_u64(out, op as u64);
}

fn emit_empty(out: &mut Vec<u8>) {
    put_op(out, Op::Empty);
}

fn emit_hash(out: &mut Vec<u8>, hash: &[u8; 32]) {
    put_op(out, Op::Hash);
    out.extend_from_slice(hash);
}

/// Reconstruct opcodes for an untouched inline MPT subtree (RLP < 32 B).
/// Walks the node so the consumer rebuilds the same bytes via
/// `PhantomLeaf` / `ExtensionHash` / synthesised branch ops — Op::Hash
/// can't be used because the parent slot expects the inline bytes, not
/// a 33-byte hash reference.
///
/// After the witness-driven enrichment of prestate (see
/// `enrich::enrich_state_leaves_from_witness` + `enrich_storage_slots_from_witness`),
/// every leaf reachable in the witness whose preimage IS in
/// `witness.keys` is in our prestate → in `touch.addrs`/`touch.slots`
/// → a target. So this function only fires for inline subtrees whose
/// leaves' preimages are missing from `witness.keys` — PhantomLeaf is
/// retained as the fallback for that residual case.
fn emit_untouched_inline(out: &mut Vec<u8>, ctx: &Ctx, raw: &[u8]) -> Result<()> {
    let (item, _) = Rlp::decode(raw)?;
    let items = item.as_list().context("inline node not a list")?;
    match items.len() {
        17 => {
            // 16-way branch, all children untouched.
            put_op(out, Op::NodeR);
            for k in 0..16 {
                let sub = subtree_child_from_rlp(&items[k])?;
                let mut buf = Vec::new();
                walk_untouched(&mut buf, ctx, sub)?;
                out.extend_from_slice(&buf);
            }
        }
        2 => {
            let path_bytes = items[0].as_bytes()?;
            let (path_nibs, is_leaf) = hp_decode(path_bytes);
            if is_leaf {
                let value_bytes = items[1].as_bytes()?;
                put_op(out, Op::PhantomLeaf);
                put_u64(out, path_nibs.len() as u64);
                for n in &path_nibs {
                    put_u64(out, *n as u64);
                }
                put_u64(out, value_bytes.len() as u64);
                out.extend_from_slice(value_bytes);
                let pad = (8 - (value_bytes.len() % 8)) % 8;
                for _ in 0..pad {
                    out.push(0);
                }
            } else {
                // Extension to an untouched child. items[1] must be a
                // 32-byte hash ref OR an inline subtree.
                match &items[1] {
                    Rlp::Bytes(b) if b.len() == 32 => {
                        let h = <[u8; 32]>::try_from(*b).unwrap();
                        put_op(out, Op::ExtensionHash);
                        put_u64(out, path_nibs.len() as u64);
                        for n in &path_nibs {
                            put_u64(out, *n as u64);
                        }
                        out.extend_from_slice(&h);
                    }
                    _ => bail!(
                        "untouched inline extension with non-hash child unsupported"
                    ),
                }
            }
        }
        n => bail!("inline node: bad shape ({} items)", n),
    }
    Ok(())
}

/// Walk an untouched subtree (helper for emit_untouched_inline's
/// recursion). Differs from walk() only in that it never expects
/// targets.
fn walk_untouched(out: &mut Vec<u8>, ctx: &Ctx, child: SubtreeChild<'_>) -> Result<()> {
    match child {
        SubtreeChild::HashRef(h) if h == EMPTY_TRIE_ROOT => emit_empty(out),
        SubtreeChild::HashRef(h) => emit_untouched_hash(out, ctx, &h)?,
        SubtreeChild::Empty => emit_empty(out),
        SubtreeChild::Inline(b) => emit_untouched_inline(out, ctx, b)?,
    }
    Ok(())
}

/// Emit opcodes for a hash-referenced untouched subtree.
///
/// After the witness-driven enrichment pass, leaves reachable in the
/// witness with a preimage in `witness.keys` are targets → the walker
/// descends through them via `walk()` and emits `Op::Leaf <idx>`. So
/// the "0 targets" case here means either:
///   * A leaf whose preimage is missing → emit `Op::PhantomLeaf` so
///     `reduce_branch` can merge prefix nibbles into the leaf path
///     during structural splits.
///   * An extension to a hash child → emit `Op::ExtensionHash` (same
///     mergeable reason).
///   * A branch or missing-preimage subtree → fall back to `Op::Hash`
///     (branches don't fold; missing-preimage subtrees weren't
///     needed for old-root computation).
fn emit_untouched_hash(out: &mut Vec<u8>, ctx: &Ctx, h: &[u8; 32]) -> Result<()> {
    if let Some(raw) = ctx.nodes.get(h) {
        let (item, _) = Rlp::decode(raw)?;
        if let Ok(items) = item.as_list() {
            if items.len() == 2 {
                let path_bytes = items[0].as_bytes()?;
                let (path_nibs, is_leaf) = hp_decode(path_bytes);
                if is_leaf {
                    let value_bytes = items[1].as_bytes()?;
                    put_op(out, Op::PhantomLeaf);
                    put_u64(out, path_nibs.len() as u64);
                    for n in &path_nibs {
                        put_u64(out, *n as u64);
                    }
                    put_u64(out, value_bytes.len() as u64);
                    out.extend_from_slice(value_bytes);
                    let pad = (8 - (value_bytes.len() % 8)) % 8;
                    for _ in 0..pad {
                        out.push(0);
                    }
                    return Ok(());
                } else {
                    // Extension. Mergeable only if its child is a 32-byte
                    // hash reference (inline-child extensions are rare;
                    // fall back to Op::Hash for those).
                    if let Rlp::Bytes(b) = &items[1] {
                        if b.len() == 32 {
                            let child_hash = <[u8; 32]>::try_from(*b).unwrap();
                            put_op(out, Op::ExtensionHash);
                            put_u64(out, path_nibs.len() as u64);
                            for n in &path_nibs {
                                put_u64(out, *n as u64);
                            }
                            out.extend_from_slice(&child_hash);
                            return Ok(());
                        }
                    }
                }
            }
            // 17-item branch or anything else — fall through to Op::Hash.
        }
    }
    emit_hash(out, h);
    Ok(())
}

// ===== walker ================================================================

/// Walk the subtree rooted at `child` with the given target set.
/// Returns true iff any target in the subtree is a write.
fn walk(
    out: &mut Vec<u8>,
    ctx: &Ctx,
    walked: &[u8],
    targets: &[Target],
    child: SubtreeChild<'_>,
    kind: TreeKind,
    owner: Option<usize>,
) -> Result<bool> {
    // 0 targets — emit the subtree as Op::Hash / Op::Empty. The MPT
    // structure below is preserved by reference; we never descend.
    if targets.is_empty() {
        match child {
            SubtreeChild::HashRef(h) if h == EMPTY_TRIE_ROOT => emit_empty(out),
            SubtreeChild::HashRef(h) => emit_untouched_hash(out, ctx, &h)?,
            SubtreeChild::Empty => emit_empty(out),
            SubtreeChild::Inline(b) => {
                // An untouched inline subtree (< 32 B) can't be
                // represented by Op::Hash because the parent expects
                // the inline RLP bytes, not a 33-byte hash ref. Walk
                // into the inline node and emit opcodes that
                // reconstruct the same bytes via ExtensionHash /
                // synthesized branches.
                emit_untouched_inline(out, ctx, b)?;
            }
        }
        return Ok(false);
    }

    // No-MPT-data subtree (synthetic insertion): we have ≥1 target
    // that needs to be inserted into a previously-empty slot. The
    // empty-trie root (kEmptyTrieRoot) is an equivalent terminator —
    // it has no node in the witness because the trie has zero
    // entries, but we still need to insert our target(s) into it.
    let is_empty_subtree = matches!(child, SubtreeChild::Empty)
        || matches!(child, SubtreeChild::HashRef(h) if h == EMPTY_TRIE_ROOT);
    if is_empty_subtree {
        if targets.len() == 1 {
            return emit_terminal_leaf(
                out, ctx, walked, &targets[0], &SubtreeChild::Empty, kind, owner,
            );
        }
        return synthesize(out, ctx, walked, targets, kind, owner);
    }

    // MPT subtree with ≥1 target — must descend so that untouched
    // sibling subtrees keep their position in the reconstructed trie.
    let raw_owned: Vec<u8>;
    let raw: &[u8] = match child {
        SubtreeChild::HashRef(h) => {
            raw_owned = ctx
                .nodes
                .get(&h)
                .ok_or_else(|| {
                    anyhow!(
                        "state_root: witness missing node 0x{} at depth {} (targets={})",
                        hex::encode(h),
                        walked.len(),
                        targets.len()
                    )
                })?
                .clone();
            &raw_owned
        }
        SubtreeChild::Inline(b) => b,
        SubtreeChild::Empty => unreachable!(),
    };

    let (item, _) = Rlp::decode(raw).context("state_root: decoding witness node")?;
    let items = item.as_list().context("state_root: node not a list")?;
    match items.len() {
        17 => walk_branch(out, ctx, walked, targets, &items, kind, owner),
        2 => walk_two_item(out, ctx, walked, targets, &items, kind, owner),
        n => bail!("state_root: unexpected MPT node shape (items={})", n),
    }
}

/// Emit `Op::Leaf` for the given target, then (for state trie) walk
/// the per-account storage subtree. Used at:
///   * Synthetic insertions into empty MPT slots.
///   * MPT-leaf nodes where the leaf's key matches our single target.
fn emit_terminal_leaf(
    out: &mut Vec<u8>,
    ctx: &Ctx,
    _walked: &[u8],
    t: &Target,
    child: &SubtreeChild<'_>,
    kind: TreeKind,
    owner: Option<usize>,
) -> Result<bool> {
    let _ = _walked;
    put_op(out, Op::Leaf);
    put_u64(out, t.leaf_idx as u64);

    if kind == TreeKind::State {
        // storage_root: extracted from the MPT leaf's value if we
        // reached it through the MPT, EMPTY_TRIE_ROOT for synthetic
        // insertions (new accounts).
        let storage_root = leaf_storage_root_if_reachable(ctx, _walked, child, t)?;

        let addr = ctx.touch.addrs[t.leaf_idx];
        let mut storage_targets: Vec<Target> = ctx
            .touch
            .slots_for(&addr)
            .into_iter()
            .map(|(slot, idx)| Target {
                key_hash: keccak256(slot.as_slice()),
                leaf_idx: idx,
                is_write: true,
            })
            .collect();
        storage_targets.sort_by_key(|t| t.key_hash);

        walk(
            out,
            ctx,
            &[],
            &storage_targets,
            SubtreeChild::HashRef(storage_root),
            TreeKind::Storage,
            Some(t.leaf_idx),
        )?;
    }
    let _ = owner;
    Ok(t.is_write)
}

/// Synthesize a branch (no MPT data) from a set of targets. All
/// children are themselves synthesized (recursive Empty subtrees).
fn synthesize(
    out: &mut Vec<u8>,
    ctx: &Ctx,
    walked: &[u8],
    targets: &[Target],
    kind: TreeKind,
    owner: Option<usize>,
) -> Result<bool> {
    let mut buckets: [Vec<Target>; 16] = Default::default();
    for t in targets {
        buckets[nibble_at(&t.key_hash, walked.len()) as usize].push(t.clone());
    }
    let mut child_bufs: [Vec<u8>; 16] = Default::default();
    let mut any_write = false;
    let mut walked_child = walked.to_vec();
    walked_child.push(0);
    for k in 0..16 {
        *walked_child.last_mut().unwrap() = k as u8;
        let hw = walk(
            &mut child_bufs[k],
            ctx,
            &walked_child,
            &buckets[k],
            SubtreeChild::Empty,
            kind,
            owner,
        )?;
        if hw {
            any_write = true;
        }
    }
    let op = if any_write { Op::NodeRw } else { Op::NodeR };
    put_op(out, op);
    for buf in &child_bufs {
        out.extend_from_slice(buf);
    }
    Ok(any_write)
}

fn walk_branch(
    out: &mut Vec<u8>,
    ctx: &Ctx,
    walked: &[u8],
    targets: &[Target],
    items: &[Rlp<'_>],
    kind: TreeKind,
    owner: Option<usize>,
) -> Result<bool> {
    let mut buckets: [Vec<Target>; 16] = Default::default();
    for t in targets {
        buckets[nibble_at(&t.key_hash, walked.len()) as usize].push(t.clone());
    }
    let mut child_bufs: [Vec<u8>; 16] = Default::default();
    let mut any_write = false;
    let mut walked_child = walked.to_vec();
    walked_child.push(0);
    for k in 0..16 {
        *walked_child.last_mut().unwrap() = k as u8;
        let sub = subtree_child_from_rlp(&items[k])?;
        let hw = walk(
            &mut child_bufs[k],
            ctx,
            &walked_child,
            &buckets[k],
            sub,
            kind,
            owner,
        )?;
        if hw {
            any_write = true;
        }
    }
    let op = if any_write { Op::NodeRw } else { Op::NodeR };
    put_op(out, op);
    for buf in &child_bufs {
        out.extend_from_slice(buf);
    }
    Ok(any_write)
}

fn walk_two_item(
    out: &mut Vec<u8>,
    ctx: &Ctx,
    walked: &[u8],
    targets: &[Target],
    items: &[Rlp<'_>],
    kind: TreeKind,
    owner: Option<usize>,
) -> Result<bool> {
    let path_bytes = items[0].as_bytes()?;
    let (path_nibs, is_leaf) = hp_decode(path_bytes);

    // First divergence point (first nibble at which not all targets
    // agree with the path). If all targets traverse the whole path, no
    // expansion is needed.
    let mut div_at: usize = path_nibs.len();
    for (i, p) in path_nibs.iter().enumerate() {
        if !targets
            .iter()
            .all(|t| nibble_at(&t.key_hash, walked.len() + i) == *p)
        {
            div_at = i;
            break;
        }
    }

    if div_at == path_nibs.len() {
        // No divergence — all targets traverse the entire path. We
        // still must wrap the path nibbles as single-child synthetic
        // branches so cpp-guest's nibbles_walked / reduce_branch
        // accumulate them into the resulting ExtR / leaf.
        let walked2: Vec<u8> = walked.iter().chain(path_nibs.iter()).copied().collect();
        let mut inner = Vec::new();
        let has_write = if is_leaf {
            if targets.len() != 1 {
                bail!(
                    "state_root: {} targets converging onto one leaf at depth {}",
                    targets.len(),
                    walked2.len()
                );
            }
            let synth_rlp = encode_two_item_rlp(
                &[],
                items[1].as_bytes()?,
                /*is_leaf=*/ true,
            );
            let leaked = Box::leak(synth_rlp.into_boxed_slice()) as &[u8];
            emit_terminal_leaf(
                &mut inner,
                ctx,
                &walked2,
                &targets[0],
                &SubtreeChild::Inline(leaked),
                kind,
                owner,
            )?
        } else {
            let sub = subtree_child_from_rlp(&items[1])?;
            walk(&mut inner, ctx, &walked2, targets, sub, kind, owner)?
        };
        wrap_with_extension(out, &mut inner, path_nibs.as_slice(), has_write);
        return Ok(has_write);
    }

    // Divergence at level `div_at`. Build the synthetic branch at that
    // depth, then wrap in `div_at` levels of single-child synthetic
    // branches for the uncontested prefix.

    let continuation_nibble = path_nibs[div_at];
    let mut buckets: [Vec<Target>; 16] = Default::default();
    for t in targets {
        let n = nibble_at(&t.key_hash, walked.len() + div_at) as usize;
        buckets[n].push(t.clone());
    }
    let continuation_targets = std::mem::take(&mut buckets[continuation_nibble as usize]);

    let mut child_bufs: [Vec<u8>; 16] = Default::default();
    let mut any_write = false;
    let walked_at_div: Vec<u8> = walked.iter().chain(&path_nibs[..div_at]).copied().collect();
    let mut walked_child = walked_at_div.clone();
    walked_child.push(0);

    for k in 0..16 {
        *walked_child.last_mut().unwrap() = k as u8;
        if k == continuation_nibble as usize {
            // CONTINUATION SLOT — the original (shortened) path + leaf/ext-child.
            let remaining = &path_nibs[div_at + 1..];
            let hw = emit_continuation(
                &mut child_bufs[k],
                ctx,
                &walked_child,
                &continuation_targets,
                remaining,
                items,
                is_leaf,
                kind,
                owner,
            )?;
            if hw {
                any_write = true;
            }
        } else {
            // DIVERGENT SLOT — targets in this bucket become fresh insertions.
            let hw = walk(
                &mut child_bufs[k],
                ctx,
                &walked_child,
                &buckets[k],
                SubtreeChild::Empty,
                kind,
                owner,
            )?;
            if hw {
                any_write = true;
            }
        }
    }

    // Synthetic branch at depth walked.len() + div_at.
    let op = if any_write { Op::NodeRw } else { Op::NodeR };
    let mut current = Vec::new();
    put_op(&mut current, op);
    for buf in &child_bufs {
        current.extend_from_slice(buf);
    }

    // Wrap in single-child synthetic branches for the uncontested
    // prefix (path_nibs[0..div_at]). reduce_branch on the consumer
    // side folds these into an ExtR.
    for i in (0..div_at).rev() {
        let p = path_nibs[i];
        let mut wrapped = Vec::new();
        put_op(&mut wrapped, op);
        for k in 0..16 {
            if k == p as usize {
                wrapped.extend(&current);
            } else {
                emit_empty(&mut wrapped);
            }
        }
        current = wrapped;
    }

    out.extend_from_slice(&current);
    Ok(any_write)
}

/// Emit the continuation slot for a divergence inside an extension/leaf.
/// `remaining` are the path nibbles still to be consumed past the
/// divergence point; the original child (items[1]) holds either the
/// account-leaf value (state) / storage-leaf value (storage) for a
/// leaf, or the next subtree's hash for an extension.
#[allow(clippy::too_many_arguments)]
fn emit_continuation(
    out: &mut Vec<u8>,
    ctx: &Ctx,
    walked: &[u8],
    targets: &[Target],
    remaining: &[u8],
    items: &[Rlp<'_>],
    is_leaf: bool,
    kind: TreeKind,
    owner: Option<usize>,
) -> Result<bool> {
    if is_leaf {
        // Leaf at depth walked.len() with `remaining.len()` path
        // nibbles still to walk.
        if targets.is_empty() {
            // Untouched sibling leaf at a divergence inside this
            // extension/leaf. After the witness-driven enrichment of
            // prestate, every leaf reachable in the witness with a
            // preimage is a target → reaching this branch implies the
            // sibling's preimage is missing from `witness.keys` (Reth
            // surfaces the leaf for structural reasons but doesn't
            // expose its address/slot preimage). Fall back to
            // Op::PhantomLeaf so the cpp-guest can re-position it
            // through reduce_branch with its raw value bytes.
            let value_bytes = items[1].as_bytes()?;
            put_op(out, Op::PhantomLeaf);
            put_u64(out, remaining.len() as u64);
            for n in remaining {
                put_u64(out, *n as u64);
            }
            put_u64(out, value_bytes.len() as u64);
            out.extend_from_slice(value_bytes);
            let pad = (8 - (value_bytes.len() % 8)) % 8;
            for _ in 0..pad {
                out.push(0);
            }
            return Ok(false);
        }
        if targets.len() == 1 && remaining.is_empty() {
            // The leaf IS our target. Emit Op::Leaf directly.
            let t = &targets[0];
            put_op(out, Op::Leaf);
            put_u64(out, t.leaf_idx as u64);
            if kind == TreeKind::State {
                let addr = ctx.touch.addrs[t.leaf_idx];
                let storage_root = mpt::account_storage_root(items[1].as_bytes()?)
                    .context("continuation leaf: decoding account RLP")?;
                let mut storage_targets: Vec<Target> = ctx
                    .touch
                    .slots_for(&addr)
                    .into_iter()
                    .map(|(slot, idx)| Target {
                        key_hash: keccak256(slot.as_slice()),
                        leaf_idx: idx,
                        is_write: true,
                    })
                    .collect();
                storage_targets.sort_by_key(|t| t.key_hash);
                walk(
                    out,
                    ctx,
                    &[],
                    &storage_targets,
                    SubtreeChild::HashRef(storage_root),
                    TreeKind::Storage,
                    Some(t.leaf_idx),
                )?;
            }
            let _ = owner;
            return Ok(t.is_write);
        }
        // ≥1 target + remaining nibbles, OR ≥2 targets at the leaf
        // (which would be a duplicate-key bug). Recursively walk a
        // synthesized 2-item subtree to consume the rest of the path.
        let synth_rlp = encode_two_item_rlp(remaining, items[1].as_bytes()?, /*is_leaf=*/ true);
        let leaked = Box::leak(synth_rlp.into_boxed_slice()) as &[u8];
        walk(
            out,
            ctx,
            walked,
            targets,
            SubtreeChild::Inline(leaked),
            kind,
            owner,
        )
    } else {
        // Extension: continuation is (remaining path) + child.
        if remaining.is_empty() {
            // Drop straight into the original child.
            let sub = subtree_child_from_rlp(&items[1])?;
            return walk(out, ctx, walked, targets, sub, kind, owner);
        }
        if targets.is_empty() {
            // Untouched sibling extension with shorter path. Emit
            // Op::ExtensionHash directly — the child must be a 32-byte
            // hash reference (inline-extension is rare and unsupported).
            let child_hash = match &items[1] {
                Rlp::Bytes(b) if b.len() == 32 => <[u8; 32]>::try_from(*b).unwrap(),
                Rlp::Bytes(b) => bail!(
                    "state_root: continuation extension child wrong length {}",
                    b.len()
                ),
                Rlp::List(_) => {
                    bail!("state_root: ExtensionHash over inline child unsupported")
                }
            };
            put_op(out, Op::ExtensionHash);
            put_u64(out, remaining.len() as u64);
            for n in remaining {
                put_u64(out, *n as u64);
            }
            out.extend_from_slice(&child_hash);
            return Ok(false);
        }
        // Recurse into a synthesized 2-item extension subtree with the
        // shorter path.
        let child_bytes = match &items[1] {
            Rlp::Bytes(b) => b,
            Rlp::List(_) => bail!("state_root: extension child as inline list unsupported here"),
        };
        let synth_rlp = encode_two_item_rlp(remaining, child_bytes, /*is_leaf=*/ false);
        let leaked = Box::leak(synth_rlp.into_boxed_slice()) as &[u8];
        walk(
            out,
            ctx,
            walked,
            targets,
            SubtreeChild::Inline(leaked),
            kind,
            owner,
        )
    }
}

/// Compute storage_root from the MPT leaf value we just descended to,
/// or EMPTY_TRIE_ROOT for synthetic-insertion accounts that don't
/// exist in the parent trie.
fn leaf_storage_root_if_reachable(
    ctx: &Ctx,
    walked: &[u8],
    child: &SubtreeChild<'_>,
    t: &Target,
) -> Result<[u8; 32]> {
    match chase_state_leaf_value(ctx, walked, child, &t.key_hash)? {
        Some(v) => mpt::account_storage_root(&v).context("storage_root: account RLP"),
        None => Ok(EMPTY_TRIE_ROOT),
    }
}

/// Walk from the current MPT subtree along `target_key` and return
/// the leaf's value bytes if the path resolves to a leaf. Returns
/// `Ok(None)` if the path hits an empty slot (account doesn't exist).
fn chase_state_leaf_value(
    ctx: &Ctx,
    walked: &[u8],
    child: &SubtreeChild<'_>,
    target_key: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let owned: Vec<u8>;
    let raw: &[u8] = match child {
        SubtreeChild::Empty => return Ok(None),
        SubtreeChild::HashRef(h) => {
            owned = ctx
                .nodes
                .get(h)
                .ok_or_else(|| anyhow!("chase: missing node 0x{}", hex::encode(h)))?
                .clone();
            &owned
        }
        SubtreeChild::Inline(b) => b,
    };

    let (item, _) = Rlp::decode(raw)?;
    let items = item.as_list()?;
    match items.len() {
        17 => {
            let depth = walked.len();
            let k = nibble_at(target_key, depth) as usize;
            let mut walked2 = walked.to_vec();
            walked2.push(k as u8);
            let sub = subtree_child_from_rlp(&items[k])?;
            chase_state_leaf_value(ctx, &walked2, &sub, target_key)
        }
        2 => {
            let path = items[0].as_bytes()?;
            let (path_nibs, is_leaf) = hp_decode(path);
            let depth = walked.len();
            // Confirm path matches target_key.
            for (i, p) in path_nibs.iter().enumerate() {
                if nibble_at(target_key, depth + i) != *p {
                    return Ok(None);
                }
            }
            let walked2: Vec<u8> = walked.iter().chain(path_nibs.iter()).copied().collect();
            if is_leaf {
                if walked2.len() != 64 {
                    bail!("chase: leaf path doesn't terminate at depth 64");
                }
                Ok(Some(items[1].as_bytes()?.to_vec()))
            } else {
                let sub = subtree_child_from_rlp(&items[1])?;
                chase_state_leaf_value(ctx, &walked2, &sub, target_key)
            }
        }
        _ => bail!("chase: bad MPT shape"),
    }
}

// ===== inline RLP helpers ====================================================

fn subtree_child_from_rlp<'a>(item: &'a Rlp<'a>) -> Result<SubtreeChild<'a>> {
    match item {
        Rlp::Bytes(b) if b.is_empty() => Ok(SubtreeChild::Empty),
        Rlp::Bytes(b) if b.len() == 32 => {
            Ok(SubtreeChild::HashRef(<[u8; 32]>::try_from(*b).unwrap()))
        }
        Rlp::Bytes(b) => bail!(
            "state_root: subtree child has wrong length {} (expected 0 or 32)",
            b.len()
        ),
        Rlp::List(_) => {
            let buf = encode_inline(item);
            // SAFETY: leaked for the duration of this run; the encoder
            // produces a one-shot stream so we don't bother tracking
            // these allocations.
            let leaked = Box::leak(buf.into_boxed_slice()) as &[u8];
            Ok(SubtreeChild::Inline(leaked))
        }
    }
}

fn encode_inline(item: &Rlp<'_>) -> Vec<u8> {
    match item {
        Rlp::Bytes(b) => encode_bytes(b),
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

fn encode_bytes(b: &[u8]) -> Vec<u8> {
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

fn be_bytes(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    out.reverse();
    out
}

fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for it in items {
        payload.extend_from_slice(it);
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

/// HP (hex-prefix) encode nibbles + is_leaf flag.
fn hp_encode(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
    let mut flag: u8 = if is_leaf { 0x20 } else { 0x00 };
    let odd = nibbles.len() % 2 == 1;
    let mut out = Vec::with_capacity(1 + nibbles.len() / 2 + 1);
    if odd {
        flag |= 0x10 | (nibbles[0] & 0x0f);
        out.push(flag);
        let mut i = 1;
        while i + 1 < nibbles.len() {
            out.push(((nibbles[i] & 0x0f) << 4) | (nibbles[i + 1] & 0x0f));
            i += 2;
        }
    } else {
        out.push(flag);
        let mut i = 0;
        while i + 1 < nibbles.len() {
            out.push(((nibbles[i] & 0x0f) << 4) | (nibbles[i + 1] & 0x0f));
            i += 2;
        }
    }
    out
}

/// RLP-encode a 2-item MPT node: [HP(path, is_leaf), value_bytes].
/// `value_bytes` is the RAW bytes from the original MPT slot (the
/// caller pre-extracted via Rlp::as_bytes), so we wrap it with the
/// appropriate RLP byte-string prefix.
fn encode_two_item_rlp(path_nibs: &[u8], value_bytes: &[u8], is_leaf: bool) -> Vec<u8> {
    let hp = hp_encode(path_nibs, is_leaf);
    let hp_rlp = encode_bytes(&hp);
    let value_rlp = encode_bytes(value_bytes);
    encode_list(&[hp_rlp, value_rlp])
}

/// Convenience wrapper for leaves specifically.
fn encode_leaf_rlp(path_nibs: &[u8], value_bytes: &[u8], _is_leaf: bool) -> Vec<u8> {
    encode_two_item_rlp(path_nibs, value_bytes, true)
}

fn keccak_arr(b: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b);
    h.finalize().into()
}

// ===== constants =============================================================

const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

// Suppress warnings for helpers retained for future Phase 5 work
// (we currently use Address indirectly via `ctx.touch.addrs`).
#[allow(dead_code)]
fn _retain(addr: Address) -> Address {
    addr
}

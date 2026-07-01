//! Witness-driven prestate construction.
//!
//! This module builds the entire `Prestate` from the
//! `debug_executionWitness` MPT alone — no `prestateTracer` is needed.
//! The witness contains every node along the path to any account/slot
//! the EVM accessed during execution, plus a `keys` field listing the
//! keccak preimages of those paths (addresses for state-trie leaves,
//! slot positions for storage-trie leaves). With those we can walk
//! the parent state trie top-down, recover the `(addr, slot)` for
//! every leaf, and populate `Prestate` with the canonical block-start
//! values.
//!
//! Why drop `prestateTracer`? It silently omits state touched only in
//! reverted frames (observed live on block 25191713). The execution
//! witness includes the surrounding MPT structure, so we get more
//! complete coverage by going to the witness directly.

use std::collections::HashMap;

use alloy::primitives::{Address, Bytes, B256, U256};
use anyhow::{anyhow, bail, Context, Result};
use tracing::info;

use crate::mpt::{hp_decode, keccak256, Rlp};
use crate::rpc::{self, AccountPrestate, ExecutionWitness, Prestate};

/// Build a complete `Prestate` from the execution witness by walking
/// the parent state trie top-down and visiting every account leaf the
/// witness exposes, then walking each account's per-account storage
/// subtree the same way.
///
/// `client` is needed only as a fallback for fetching bytecode whose
/// `code_hash` appears in the state-trie leaf but isn't present in
/// `witness.codes` (rare, but happens when the code wasn't EXTCODE'd
/// during this block's execution).
///
/// Leaves whose key preimage is missing from `witness.keys` are
/// skipped here — the state-root walker will emit `Op::Hash` for them
/// so the trie still reconstructs correctly. The cpp-guest never
/// needs to look these slots up at runtime because the EVM only
/// accesses what has a preimage.
pub async fn build_prestate_from_witness(
    client: &rpc::Client,
    parent_state_root: B256,
    parent_hash: B256,
    witness: &ExecutionWitness,
) -> Result<Prestate> {
    // Index nodes by their keccak hash for fast traversal.
    let mut nodes: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(witness.state.len());
    for raw in &witness.state {
        if raw.len() < 32 {
            continue;
        }
        nodes.insert(keccak256(raw), raw.to_vec());
    }

    // Preimage tables: keccak(key) → key. Reth's witness.keys mixes
    // 20-byte addresses (state-trie keys) and 32-byte slot positions
    // (storage-trie keys), so dispatch by length.
    let mut addr_preimage: HashMap<[u8; 32], Address> = HashMap::new();
    let mut slot_preimage: HashMap<[u8; 32], B256> = HashMap::new();
    for k in &witness.keys {
        match k.len() {
            20 => {
                let mut a = [0u8; 20];
                a.copy_from_slice(k);
                addr_preimage.insert(keccak256(k.as_ref()), Address::from(a));
            }
            32 => {
                let mut p = [0u8; 32];
                p.copy_from_slice(k);
                slot_preimage.insert(keccak256(k.as_ref()), B256::from(p));
            }
            _ => { /* unknown preimage shape; ignore */ }
        }
    }

    // codes_by_hash: needed both to attach `code` to discovered
    // accounts and as the first lookup before falling back to RPC.
    let mut codes_by_hash: HashMap<[u8; 32], Bytes> = HashMap::new();
    for c in &witness.codes {
        codes_by_hash.insert(keccak256(c), c.clone());
    }

    // Step 1: collect every leaf in the parent state trie.
    let mut state_leaves: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    collect_leaves(
        &nodes,
        &parent_state_root.0,
        &mut Vec::new(),
        &mut state_leaves,
    )?;

    let mut prestate = Prestate::default();
    let mut state_missing = 0usize;
    let mut storage_missing = 0usize;

    for (path_hash, account_rlp) in state_leaves {
        let addr = match addr_preimage.get(&path_hash) {
            Some(a) => *a,
            None => {
                // The state-root walker will emit Op::Hash for this
                // leaf so the trie still verifies — the cpp-guest
                // never accesses it because the EVM didn't either.
                state_missing += 1;
                continue;
            }
        };
        let (nonce, balance, sroot, code_hash) = decode_account_rlp(&account_rlp)?;
        let mut entry = AccountPrestate {
            nonce: Some(nonce),
            balance: Some(balance),
            ..Default::default()
        };
        if code_hash != EMPTY_CODE_HASH {
            if let Some(c) = codes_by_hash.get(&code_hash) {
                entry.code = Some(c.clone());
            } else {
                let c = client.code_at_hash(addr, parent_hash).await?;
                if keccak256(&c) != code_hash {
                    bail!(
                        "build_prestate: eth_getCode for {} returned code hashing to {} != chain leaf's {}",
                        addr,
                        hex::encode(keccak256(&c)),
                        hex::encode(code_hash)
                    );
                }
                entry.code = Some(c);
            }
        }

        // Step 2: walk the per-account storage trie for this addr.
        if sroot != EMPTY_TRIE_ROOT {
            let mut storage_leaves: Vec<([u8; 32], Vec<u8>)> = Vec::new();
            collect_leaves(&nodes, &sroot, &mut Vec::new(), &mut storage_leaves)?;
            for (slot_hash, value_rlp) in storage_leaves {
                let pos = match slot_preimage.get(&slot_hash) {
                    Some(p) => *p,
                    None => {
                        storage_missing += 1;
                        continue;
                    }
                };
                let (val_item, _) = Rlp::decode(&value_rlp)?;
                let val_bytes = val_item.as_bytes()?;
                let mut padded = [0u8; 32];
                padded[32 - val_bytes.len()..].copy_from_slice(val_bytes);
                entry.storage.insert(pos, B256::from(padded));
            }
        }

        prestate.insert(addr, entry);
    }

    info!(
        accounts = prestate.len(),
        storage_slots = prestate.values().map(|p| p.storage.len()).sum::<usize>(),
        state_leaves_missing_preimage = state_missing,
        storage_leaves_missing_preimage = storage_missing,
        "built prestate from witness",
    );
    Ok(prestate)
}

/// Append every account leaf reachable in the witness state trie to
/// `prestate` (if not already present). Used so the state-root walker
/// can emit `Op::Leaf <idx>` for off-target sibling leaves instead of
/// the legacy `Op::PhantomLeaf` carry-bytes trick — every leaf the
/// walker encounters now has an idx into prestate.
///
/// Leaves whose address preimage is missing from `witness.keys` are
/// skipped; the walker handles them via `Op::Hash` at the leaf's
/// position.
pub async fn enrich_state_leaves_from_witness(
    client: &rpc::Client,
    parent_state_root: B256,
    parent_hash: B256,
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
    let mut addr_preimage: HashMap<[u8; 32], Address> = HashMap::new();
    for k in &witness.keys {
        if k.len() == 20 {
            let mut a = [0u8; 20];
            a.copy_from_slice(k);
            addr_preimage.insert(keccak256(k.as_ref()), Address::from(a));
        }
    }
    let mut codes_by_hash: HashMap<[u8; 32], Bytes> = HashMap::new();
    for c in &witness.codes {
        codes_by_hash.insert(keccak256(c), c.clone());
    }

    let mut state_leaves: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    collect_leaves(
        &nodes,
        &parent_state_root.0,
        &mut Vec::new(),
        &mut state_leaves,
    )?;

    let mut added = 0usize;
    let mut missing_preimage = 0usize;
    for (path_hash, account_rlp) in state_leaves {
        let addr = match addr_preimage.get(&path_hash) {
            Some(a) => *a,
            None => {
                missing_preimage += 1;
                continue;
            }
        };
        if prestate.contains_key(&addr) {
            continue;
        }
        let (nonce, balance, _sroot, code_hash) = decode_account_rlp(&account_rlp)?;
        let mut entry = AccountPrestate {
            nonce: Some(nonce),
            balance: Some(balance),
            ..Default::default()
        };
        if code_hash != EMPTY_CODE_HASH {
            if let Some(c) = codes_by_hash.get(&code_hash) {
                entry.code = Some(c.clone());
            } else {
                let c = client.code_at_hash(addr, parent_hash).await?;
                if keccak256(&c) != code_hash {
                    bail!(
                        "enrich_state_leaves: eth_getCode for {} hashes to {} != chain leaf's {}",
                        addr,
                        hex::encode(keccak256(&c)),
                        hex::encode(code_hash)
                    );
                }
                entry.code = Some(c);
            }
        }
        prestate.insert(addr, entry);
        added += 1;
    }

    info!(
        added,
        missing_preimage, "appended state-trie leaves into prestate"
    );
    Ok(added)
}

/// Inject every address that appears in the prestate diff but isn't
/// already in `prestate` — these are accounts CREATEd this block (no
/// leaf in the parent trie). Empty entries; values get filled by the
/// EVM execution and end up in the post-state via `write_accounts`'s
/// is_read_only=false flagging.
pub fn inject_diff_addresses(prestate: &mut Prestate, diff: &crate::rpc::PrestateDiff) {
    let mut added = 0usize;
    for side in [&diff.pre, &diff.post] {
        for (addr, info) in side {
            let entry = prestate.entry(*addr).or_insert_with(|| {
                added += 1;
                AccountPrestate::default()
            });
            if entry.balance.is_none() {
                entry.balance = info.balance;
            }
            if entry.nonce.is_none() {
                entry.nonce = info.nonce;
            }
            if entry.code.is_none() && info.code.is_some() {
                entry.code = info.code.clone();
            }
            // Storage slots from diff.pre carry the block-start values
            // for slots that aren't visible in the witness storage
            // trie (e.g. slots only touched in reverted frames; or
            // chain.diff.pre entries that have value=0 implicitly).
            for (slot, val) in &info.storage {
                prestate
                    .get_mut(addr)
                    .unwrap()
                    .storage
                    .entry(*slot)
                    .or_insert(*val);
            }
        }
    }
    info!(
        added_accounts = added,
        "injected diff addresses into prestate"
    );
}

/// Inject every address that appears as a tx sender or `to` field —
/// these are guaranteed to be EVM-accessed (sender pays gas; `to` is
/// the callee). Empty entries if not already present.
pub fn inject_tx_addresses(prestate: &mut Prestate, current: &alloy::rpc::types::Block) {
    use alloy::consensus::TxEnvelope;
    use alloy::network::TransactionResponse as _;
    use alloy::rpc::types::BlockTransactions;
    let mut added = 0usize;
    if let BlockTransactions::Full(txs) = &current.transactions {
        for tx in txs {
            if prestate
                .entry(tx.from())
                .or_insert_with(|| {
                    added += 1;
                    AccountPrestate::default()
                })
                .balance
                .is_none()
            {
                // sender will be filled by witness walk if it exists in
                // parent trie; otherwise stays empty until tx execution.
            }
            if let Some(to) = tx_to(&tx.inner) {
                prestate.entry(to).or_insert_with(|| {
                    added += 1;
                    AccountPrestate::default()
                });
            }
            // NOTE: EIP-2930 access-list addrs/slots are deliberately NOT
            // injected. The access list only *declares* state a tx may
            // touch (pre-paying the warm cost); the tx may never actually
            // access it, so reth's witness omits the unaccessed entries.
            // Injecting them unconditionally put accounts/slots into the
            // prestate that aren't in the witness tree — their pre-block
            // subtree is collapsed to a hash, so the state-root walk can't
            // reach them. The genuinely-accessed access-list entries are
            // already captured by the prestate tracer + witness; if reth
            // didn't need an entry, neither do we. (Injecting them also
            // seeded slots with 0, which `enrich_storage` then skipped as
            // "already present", masking real non-zero values.)
            // EIP-7702 authorization signers.
            if let TxEnvelope::Eip7702(signed) = &*tx.inner {
                for auth in &signed.tx().authorization_list {
                    if let Ok(sig) = auth.signature() {
                        if let Ok(vk) = sig.recover_from_prehash(&auth.inner().signature_hash()) {
                            let pt = vk.to_encoded_point(false);
                            let bytes = pt.as_bytes();
                            if bytes.len() == 65 && bytes[0] == 0x04 {
                                let h = keccak256(&bytes[1..]);
                                let mut a = [0u8; 20];
                                a.copy_from_slice(&h[12..]);
                                prestate.entry(Address::from(a)).or_insert_with(|| {
                                    added += 1;
                                    AccountPrestate::default()
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    info!(
        added_addresses = added,
        "injected tx-derived addresses into prestate"
    );
}

fn tx_to(env: &alloy::consensus::TxEnvelope) -> Option<Address> {
    use alloy::consensus::Transaction as _;
    env.to()
}

pub async fn enrich_prestate_from_witness(
    client: &rpc::Client,
    parent_state_root: B256,
    parent_hash: B256,
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
    let mut walk_skipped = 0usize;
    let addrs: Vec<Address> = prestate.keys().copied().collect();
    for addr in addrs {
        let addr_hash = keccak256(addr.as_slice());
        let leaf = match walk_to_leaf(&nodes, &parent_state_root.0, &addr_hash) {
            Ok(Some(v)) => v,
            Ok(None) => continue, // account doesn't exist in parent trie
            Err(e) if is_witness_missing(&e) => {
                // Witness gap (see verify::is_witness_missing): reth's
                // debug_executionWitness occasionally references an
                // address whose state-trie path crosses a node not
                // included in `witness.state`. Skip patching this
                // account — its values from prestateTracer remain. If
                // cpp-guest actually accesses this account at runtime,
                // the post-state-root walker will surface any real
                // problem.
                tracing::warn!(addr = %addr, err = %e, "enrich: state-trie walk skipped (witness gap)");
                walk_skipped += 1;
                continue;
            }
            Err(e) => return Err(e),
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
                let c = client.code_at_hash(addr, parent_hash).await?;
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

    info!(
        patched_accounts = patched,
        walk_skipped, "enriched prestate from witness"
    );
    Ok(patched)
}

/// Discover storage slots touched by the EVM that Geth's `prestateTracer`
/// omits (notably: slots whose only access is inside a reverted frame —
/// the tracer reports the account but with empty `storage`). The
/// `debug_executionWitness` MPT nevertheless includes every storage
/// trie node the EVM touched, so we can recover those slots by walking
/// each touched account's parent storage trie and using `witness.keys`
/// to invert the trie path (keccak256(slot_pos)) back to the slot
/// position. Slots already in `prestate.storage` are left untouched;
/// new entries are inserted with their canonical pre-block value.
///
/// Returns the number of (addr, slot) pairs newly inserted.
pub fn enrich_storage_slots_from_witness(
    parent_state_root: B256,
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

    // Preimage table: trie path (keccak of slot position) → slot position.
    // `witness.keys` mixes 20-byte addresses and 32-byte slot positions —
    // we only care about the 32-byte entries here.
    let mut slot_preimage: HashMap<[u8; 32], B256> = HashMap::new();
    for k in &witness.keys {
        if k.len() == 32 {
            let pos = B256::from_slice(k);
            slot_preimage.insert(keccak256(k.as_ref()), pos);
        }
    }

    let mut added = 0usize;
    let mut missing_preimage = 0usize;
    let mut walk_skipped = 0usize;
    let addrs: Vec<Address> = prestate.keys().copied().collect();
    for addr in addrs {
        let addr_hash = keccak256(addr.as_slice());
        let leaf = match walk_to_leaf(&nodes, &parent_state_root.0, &addr_hash) {
            Ok(Some(v)) => v,
            Ok(None) => continue, // account doesn't exist in parent trie → no storage
            Err(e) if is_witness_missing(&e) => {
                // Witness gap on the state-trie walk — can't reach
                // this account's storage root, so no slots to enrich.
                // The address's existing prestate values (from
                // prestateTracer) stay; cpp-guest's post-state-root
                // walker will surface any real divergence downstream.
                tracing::warn!(addr = %addr, err = %e, "enrich storage: state-trie walk skipped (witness gap)");
                walk_skipped += 1;
                continue;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "enrich: walking parent state trie for addr {addr} (hash 0x{})",
                        hex::encode(addr_hash)
                    )
                })
            }
        };
        let (_nonce, _balance, sroot, _ch) = decode_account_rlp(&leaf)?;
        if sroot == EMPTY_TRIE_ROOT {
            continue;
        }

        // Collect every storage leaf reachable from this root.
        let mut leaves: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        collect_leaves(&nodes, &sroot, &mut Vec::new(), &mut leaves)?;
        for (path_hash, value_rlp) in leaves {
            let pos = match slot_preimage.get(&path_hash) {
                Some(p) => *p,
                None => {
                    missing_preimage += 1;
                    continue;
                }
            };
            // Reachability check: even though collect_leaves found this
            // leaf via DFS, the strict `walk_to_leaf` (which the
            // downstream state_root::write uses to build the trie ops
            // for cpp-guest) MUST also reach it. reth's witness can be
            // inconsistent here: collect_leaves may reach a leaf
            // through an inline / alternate subtree representation,
            // while walk_to_leaf descends the canonical path and hits
            // a missing intermediate node. If we added the slot here
            // anyway, state_root::write would fatal later. Skip in
            // that case — the slot stays out of prestate, and any
            // SLOAD that actually needs it surfaces a real bug
            // through cpp-guest's reconstruction.
            match walk_to_leaf(&nodes, &sroot, &path_hash) {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    walk_skipped += 1;
                    continue;
                }
            }
            let entry = prestate.get_mut(&addr).unwrap();
            if entry.storage.contains_key(&pos) {
                continue;
            }
            // Storage leaf value is RLP(uint256_minimal). Decode to B256.
            let (val_item, _) = Rlp::decode(&value_rlp)?;
            let val_bytes = val_item.as_bytes()?;
            let mut padded = [0u8; 32];
            padded[32 - val_bytes.len()..].copy_from_slice(val_bytes);
            entry.storage.insert(pos, B256::from(padded));
            added += 1;
        }
    }

    info!(
        added_slots = added,
        missing_preimage = missing_preimage,
        walk_skipped,
        "enriched prestate.storage from witness storage tries"
    );
    Ok(added)
}

/// DFS over the trie rooted at `root_hash`, accumulating every leaf as
/// (full_path_hash, raw_value_bytes). `path_nibs` carries the nibbles
/// walked from the root so far; on each leaf we reconstruct the full
/// 32-byte path = pack(path_nibs + leaf_hp_nibs).
pub(crate) fn collect_leaves(
    nodes: &HashMap<[u8; 32], Vec<u8>>,
    root_hash: &[u8; 32],
    path_nibs: &mut Vec<u8>,
    out: &mut Vec<([u8; 32], Vec<u8>)>,
) -> Result<()> {
    if root_hash == &EMPTY_TRIE_ROOT {
        return Ok(());
    }
    let raw = match nodes.get(root_hash) {
        Some(v) => v.clone(),
        None => return Ok(()), // partial witness: subtree we can't see
    };
    collect_leaves_raw(nodes, &raw, path_nibs, out)
}

fn collect_leaves_raw(
    nodes: &HashMap<[u8; 32], Vec<u8>>,
    raw: &[u8],
    path_nibs: &mut Vec<u8>,
    out: &mut Vec<([u8; 32], Vec<u8>)>,
) -> Result<()> {
    let (item, _) = Rlp::decode(raw)?;
    let items = item.as_list()?;
    match items.len() {
        17 => {
            for nib in 0u8..16 {
                path_nibs.push(nib);
                collect_child(nodes, &items[nib as usize], path_nibs, out)?;
                path_nibs.pop();
            }
        }
        2 => {
            let path = items[0].as_bytes()?;
            let (extra_nibs, is_leaf) = hp_decode(path);
            let push_n = extra_nibs.len();
            for n in &extra_nibs {
                path_nibs.push(*n);
            }
            if is_leaf {
                if path_nibs.len() == 64 {
                    let mut full = [0u8; 32];
                    for i in 0..32 {
                        full[i] = (path_nibs[2 * i] << 4) | path_nibs[2 * i + 1];
                    }
                    let val = items[1].as_bytes()?.to_vec();
                    out.push((full, val));
                }
                // else: a leaf whose path doesn't reach a full 32-byte
                // hash — would be a state-trie account leaf hit by accident
                // if `root_hash` was a state-root. Storage tries always
                // have 64-nibble paths; skip anything shorter.
            } else {
                collect_child(nodes, &items[1], path_nibs, out)?;
            }
            for _ in 0..push_n {
                path_nibs.pop();
            }
        }
        _ => bail!("collect_leaves: bad MPT shape ({} items)", items.len()),
    }
    Ok(())
}

fn collect_child(
    nodes: &HashMap<[u8; 32], Vec<u8>>,
    child: &Rlp<'_>,
    path_nibs: &mut Vec<u8>,
    out: &mut Vec<([u8; 32], Vec<u8>)>,
) -> Result<()> {
    match child {
        Rlp::Bytes([]) => Ok(()),
        Rlp::Bytes(b) if b.len() == 32 => {
            let h = <[u8; 32]>::try_from(*b).unwrap();
            collect_leaves(nodes, &h, path_nibs, out)
        }
        Rlp::Bytes(_) => Ok(()), // partial / unsupported
        Rlp::List(_) => {
            let buf = encode_inline(child);
            collect_leaves_raw(nodes, &buf, path_nibs, out)
        }
    }
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
        Rlp::Bytes([]) => Ok(None),
        Rlp::Bytes(b) if b.len() == 32 => {
            let h = <[u8; 32]>::try_from(*b).unwrap();
            let raw = nodes
                .get(&h)
                .ok_or_else(|| anyhow!("enrich: witness missing 0x{}", hex::encode(h)))?
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

/// Detect "witness missing trie node" errors emitted by `walk_to_leaf`
/// / `follow_child`. Mirrors `verify::is_witness_missing` — kept local
/// to avoid a cross-module import. See that copy for the rationale.
fn is_witness_missing(err: &anyhow::Error) -> bool {
    let s = format!("{err:#}");
    s.contains("witness missing")
}

fn nibble(hash: &[u8; 32], i: usize) -> u8 {
    let b = hash[i / 2];
    if i.is_multiple_of(2) {
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
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

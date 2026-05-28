//! Ordered touch sets shared across the Accounts/Storages/StateRoot
//! writers. Building this once guarantees the three sections agree on
//! the index assignments (Accounts[idx] / Storages[idx]) that the
//! StateRoot stream's `Op::Leaf` opcodes reference.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use alloy::primitives::{Address, B256};

use crate::rpc::{Prestate, PrestateDiff};

pub struct TouchSet {
    /// Addresses in the same iteration order as `write_accounts`.
    pub addrs: Vec<Address>,
    /// addr -> index into `addrs` (= account_idx).
    pub addr_idx: HashMap<Address, usize>,

    /// (addr, slot) pairs in the same iteration order as `write_storages`.
    pub slots: Vec<(Address, B256)>,
    /// (addr, slot) -> index into `slots` (= storage_idx).
    pub slot_idx: HashMap<(Address, B256), usize>,
}

impl TouchSet {
    pub fn build(prestate: &Prestate, diff: &PrestateDiff) -> Self {
        // Addresses — same union as sections::write_accounts.
        let mut addr_set: BTreeSet<Address> = prestate.keys().copied().collect();
        addr_set.extend(diff.pre.keys().copied());
        addr_set.extend(diff.post.keys().copied());
        let addrs: Vec<Address> = addr_set.into_iter().collect();
        let addr_idx = addrs
            .iter()
            .enumerate()
            .map(|(i, a)| (*a, i))
            .collect();

        // (addr, slot) pairs — same union as sections::write_storages.
        let mut slot_set: BTreeSet<(Address, B256)> = BTreeSet::new();
        for (addr, ps) in prestate {
            for slot in ps.storage.keys() {
                slot_set.insert((*addr, *slot));
            }
        }
        for side in [&diff.pre, &diff.post] {
            for (addr, info) in side {
                for slot in info.storage.keys() {
                    slot_set.insert((*addr, *slot));
                }
            }
        }
        let slots: Vec<(Address, B256)> = slot_set.into_iter().collect();
        let slot_idx = slots
            .iter()
            .enumerate()
            .map(|(i, k)| (*k, i))
            .collect();

        Self { addrs, addr_idx, slots, slot_idx }
    }

    /// Touched slots for one account, in `slots` order. Used by the
    /// StateRoot encoder to walk the per-account storage trie.
    pub fn slots_for(&self, addr: &Address) -> Vec<(B256, usize)> {
        // `slots` is sorted by (addr, slot) so all entries for `addr`
        // are contiguous; binary-search the range bounds.
        let start = self
            .slots
            .partition_point(|(a, _)| a < addr);
        let end = self
            .slots
            .partition_point(|(a, _)| a <= addr);
        (start..end)
            .map(|i| {
                let (_, slot) = self.slots[i];
                (slot, i)
            })
            .collect()
    }

    /// Whether every entry in `slots` for this account is read-only.
    /// Useful for the encoder's NodeR-vs-NodeRW decision on the storage
    /// subtree. The accounts table's own `is_read_only` flag is derived
    /// from `diff` outside (see sections::write_accounts) and the same
    /// derivation lives in the writer; this helper is symmetric.
    pub fn is_written_addr(&self, addr: &Address, diff: &PrestateDiff) -> bool {
        diff.pre.contains_key(addr) || diff.post.contains_key(addr)
    }

    pub fn is_written_slot(
        &self,
        addr: &Address,
        slot: &B256,
        diff: &PrestateDiff,
    ) -> bool {
        for side in [&diff.pre, &diff.post] {
            if let Some(info) = side.get(addr) {
                if info.storage.contains_key(slot) {
                    return true;
                }
            }
        }
        false
    }
}

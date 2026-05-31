// DynamicStorage — per-tx scratchpad of storage slots for accounts that
// were freshly CREATEd in the current transaction.
//
// Motivation: reth's witness recorder gates storage iteration on
// `account.account.is_some()`, so any slot SSTORE'd on an account that
// later SELFDESTRUCTs in the same tx is silently dropped from the
// manifest. The static `Storages` table built from the manifest then
// fatals on the SLOAD/SSTORE — see
// `test_set_code_to_self_destructing_account_deployed_in_same_tx`.
//
// Safety: addresses where `init_create_account` succeeded this tx
// provably did not exist in the parent state trie (the witness attests
// this via the absent/empty leaf at that address). Their original
// storage is implicitly 0 for every slot, so a malicious prover cannot
// forge any value — whatever the EVM SSTOREs is uncontested.
//
// Lifecycle:
//   * `set_value(addr, pos, v)` — first SSTORE on a fresh account
//     auto-creates the (addr, pos) entry with value=v.
//   * SLOAD reads return `value()` (= 0 if absent, matching "fresh
//     account has no prior storage" semantics).
//   * On SELFDESTRUCT, `erase_account(addr)` drops every slot for the
//     account in O(1) (the destructor walks the inner map but we don't
//     pay a lookup-iteration cost like a flat map would).
//   * At tx-end, surviving accounts (= still in `entries_`) have their
//     slots committed back to the canonical `Storages` table by the
//     caller (currently unimplemented — see ZiskStateDB tx-end hook).
//
// Choice of `std::unordered_map<addr, unordered_map<pos, Slot>>`:
// nested unordered_map gives O(1) lookup AND O(1) per-account erase
// (the differentiating requirement vs a flat std::map<(addr,pos),Slot>
// which would need a range-erase). Iteration over an account's slots
// is O(K) — needed for tx-end commit + the SELFDESTRUCT snapshot.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg {

class DynamicStorage {
public:
    // Per-slot scratch state. Mirrors `Storages::Mods` for the
    // warm/cold + EIP-2200 per-tx-original semantics.
    struct Slot {
        evmc::bytes32 value{};        // current value; block-original is implicitly 0
        uint64_t      last_tx_idx{0}; // 0 = never-touched; tx counter starts at 1
        evmc::bytes32 tx_original{};  // snapshot at start of last-touching tx (EIP-2200)
    };

    // Erased-account snapshot used by SELFDESTRUCT journaling: lets a
    // reverted SELFDESTRUCT frame restore the account's entire storage
    // map in one `restore_account` call.
    using SlotPair = std::pair<evmc::bytes32, Slot>;
    using Snapshot = std::vector<SlotPair>;

    // --- Reads ---

    // True iff the account has any (addr, *) entry in the table.
    bool contains(const evmc::address& addr) const noexcept;

    // True iff the (addr, pos) entry exists.
    bool contains(const evmc::address& addr,
                  const evmc::bytes32& pos) const noexcept;

    // Current value at (addr, pos); returns zero if absent — matches
    // "fresh account has no prior storage" semantics.
    evmc::bytes32 value(const evmc::address& addr,
                        const evmc::bytes32& pos) const noexcept;

    // EIP-2200 per-tx-original. Returns `Slot::tx_original` if the
    // slot was touched in `tx_idx`; otherwise returns 0 (the
    // implicit block-original for a fresh account).
    evmc::bytes32 tx_original(const evmc::address& addr,
                              const evmc::bytes32& pos,
                              uint64_t              tx_idx) const noexcept;

    // EIP-2929 warm/cold predicate.
    bool is_warm(const evmc::address& addr,
                 const evmc::bytes32& pos,
                 uint64_t              tx_idx) const noexcept;

    // Raw last_tx_idx for journal capture.
    uint64_t last_tx_idx(const evmc::address& addr,
                         const evmc::bytes32& pos) const noexcept;

    // --- Writes ---

    // Set the slot's current value. Inserts the (addr, pos) entry if
    // absent and also creates the per-addr inner map if first slot for
    // that address. Sets `last_tx_idx = tx_idx` atomically (same
    // "value + warmth together" convention as `Storages::set_value_at`).
    // Returns true if the (addr, pos) entry was absent before this call
    // (= a new row was created); the caller uses this to decide whether
    // the journal entry's `was_present` flag is false.
    bool set_value(const evmc::address& addr,
                   const evmc::bytes32& pos,
                   const evmc::bytes32& v,
                   uint64_t              tx_idx);

    // Snapshot current value into tx_original and bump last_tx_idx if
    // this is the first touch in `tx_idx`. Idempotent within a tx.
    // Auto-inserts the (addr, pos) entry if absent — needed because
    // EIP-2929 access_storage runs BEFORE the first SLOAD/SSTORE and
    // must register the slot for the subsequent operations.
    void mark_touched(const evmc::address& addr,
                      const evmc::bytes32& pos,
                      uint64_t              tx_idx);

    // --- Journal restore paths ---

    // Restore slot to a known (value, last_tx_idx) — used by the
    // journal's `DynStorageEntry::was_present == true` rollback.
    void restore_slot(const evmc::address& addr,
                      const evmc::bytes32& pos,
                      const evmc::bytes32& v,
                      uint64_t              last_tx_idx);

    // Remove a single slot. Used by the journal's
    // `DynStorageEntry::was_present == false` rollback. If this leaves
    // the inner map empty, the outer entry is also erased.
    void unset_slot(const evmc::address& addr,
                    const evmc::bytes32& pos);

    // Restore just the warm/cold state (for `DynStorageWarmEntry`).
    void set_warm(const evmc::address& addr,
                  const evmc::bytes32& pos,
                  uint64_t              last_tx_idx);

    // --- SELFDESTRUCT path ---

    // Drop every slot for the account in O(1). Returns the dropped
    // entries so the journal can capture them for revert.
    Snapshot erase_account(const evmc::address& addr);

    // Re-insert a snapshot returned by `erase_account`. Used by the
    // journal's `DynAccountEraseEntry` rollback.
    void restore_account(const evmc::address& addr, Snapshot&& snap);

    // --- Tx-end commit hook ---

    // True iff there are any entries left for any account — used by the
    // tx-end commit path to know whether commit work is needed.
    bool empty() const noexcept { return entries_.empty(); }

    // Read-only access to the underlying map for iteration in the
    // tx-end commit path. Surviving entries are committed to the
    // canonical Storages table; destroyed accounts are no longer
    // present (erase_account removed them).
    const auto& entries() const noexcept { return entries_; }

    // Discard everything. Called at block-end (or any point the caller
    // knows nothing should carry over).
    void clear() noexcept { entries_.clear(); }

private:
    struct AddressHash {
        size_t operator()(const evmc::address& a) const noexcept {
            uint64_t v;
            std::memcpy(&v, a.bytes + sizeof(a.bytes) - 8, 8);
            return static_cast<size_t>(v);
        }
    };
    struct AddressEq {
        bool operator()(const evmc::address& x,
                        const evmc::address& y) const noexcept {
            return std::memcmp(x.bytes, y.bytes, sizeof(x.bytes)) == 0;
        }
    };
    struct Bytes32Hash {
        size_t operator()(const evmc::bytes32& b) const noexcept {
            uint64_t v;
            std::memcpy(&v, b.bytes + sizeof(b.bytes) - 8, 8);
            return static_cast<size_t>(v);
        }
    };
    struct Bytes32Eq {
        bool operator()(const evmc::bytes32& x,
                        const evmc::bytes32& y) const noexcept {
            return std::memcmp(x.bytes, y.bytes, sizeof(x.bytes)) == 0;
        }
    };

    using InnerMap = std::unordered_map<evmc::bytes32, Slot,
                                        Bytes32Hash, Bytes32Eq>;

    std::unordered_map<evmc::address, InnerMap,
                       AddressHash, AddressEq> entries_;
};

} // namespace zeg

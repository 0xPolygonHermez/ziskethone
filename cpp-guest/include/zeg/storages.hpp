// Storages — per-account storage-slot table for the ZisK Ethereum guest.
//
// Holds, for every (account, slot) pair the block touches:
//   * the *original* (block-start) slot value, and
//   * an in-memory dirty/new-value pair tracking any SSTORE performed
//     during EVM re-execution.
//
// Like Accounts, the table is no longer parsed from a stream section: it
// is built by `StateRoot`'s old-root walk via `append` (one row per
// storage-trie leaf — the leaf opcode carries position + original value;
// the owning address comes from the enclosing account leaf). Originals
// live in an owned buffer `reserve`d exactly from `numberOfStorages`.
//
// Lookup is by the composite (address, position) pair through an internal
// hashmap. Both halves are already pseudo-random (keccak outputs / slot
// indices), so the custom hasher just XORs the lowest 8 bytes of each.

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>           // std::assume_aligned
#include <unordered_map>
#include <vector>

#include <evmc/evmc.hpp>

#include "zeg/trie_node.hpp"

namespace zeg {

class Storages {
public:
    // Internal record stride in bytes. Documented in `View` below. No
    // longer a wire size — the table is built via `append`, not parsed.
    static constexpr uint64_t kRecordSize = 88;

    // Starts empty. Call `reserve(numberOfStorages)` once, then `append`
    // one row per storage-trie leaf during the StateRoot old-root walk.
    Storages() = default;

    // Pre-size the owned record buffer to exactly `count` rows. Must be
    // called before any `append`; the buffer is fixed at this size so
    // `View` pointers stay stable, and `append` fatals on overflow.
    void reserve(uint64_t count);

    // Append one storage row (original/block-start value) and return its
    // index. Registers (address, position) in the lookup map and the
    // per-address slot list. Fatals on overflow past `reserve`.
    size_t append(const evmc::address& address,
                  const evmc::bytes32& position,
                  const evmc::bytes32& value);

    // Returns the current slot value: the dirty new value if `set_value`
    // has been called for this (addr, position), else the original from
    // the stream. Aborts via zeg::fatal if (addr, position) is not
    // present. Also touches the slot for tx `tx_idx` (snapshots the
    // pre-tx value into `tx_original_at(idx)` if this is the first
    // access in this tx) so the EVM sees the correct EIP-2929 warm
    // state and EIP-2200 original on subsequent calls. The cold→warm
    // transition is NOT journaled here; the caller (ZiskStateDB)
    // captures it via `Journal::log_storage_warm` when running inside
    // a revertible EVM frame.
    evmc::bytes32 value(const evmc::address& addr,
                        const evmc::bytes32& position,
                        uint64_t              tx_idx);

    // Records a new value for the slot. Aborts via zeg::fatal if (addr,
    // position) is not present. Touches the slot for `tx_idx` (same
    // snapshot semantics as `value()`).
    void set_value(const evmc::address& addr,
                   const evmc::bytes32& position,
                   const evmc::bytes32& v,
                   uint64_t              tx_idx);

    // By-index write accessor. Skips the hashmap lookup; useful for the
    // journal's rollback path where the index is already known. Atomic:
    // sets the slot value AND `last_tx_idx` in one call, so the same
    // setter handles both forward writes (caller passes `tx_counter_`)
    // and journal rollback (caller passes the pre-write `old_last_tx_idx`).
    void set_value_at(size_t idx, const evmc::bytes32& v, uint64_t tx_idx);

    // By-index read accessors. `value_at` returns the *current* value
    // (modification if dirty, else original); `value_orig_at` always
    // returns the original from the input stream. address / position
    // are immutable post-construction so a single accessor suffices.
    const evmc::address&  address_at     (size_t idx) const noexcept;
    const evmc::bytes32&  position_at    (size_t idx) const noexcept;
    evmc::bytes32         value_at       (size_t idx) const noexcept;
    const evmc::bytes32&  value_orig_at  (size_t idx) const noexcept;

    // ----- storage-trie leaf node (owned per row) -----
    //
    // Each row caches the `NodeR` result of its storage-trie leaf and the
    // keccak(position) used to rebuild the leaf path. `build_value`
    // (old-root pass) builds the cached leaf from the ORIGINAL value at path
    // `nib`; `update_value` (new-root pass) recomputes it ONLY if the slot
    // value changed. Both return a pointer to the row's cached union.
    const NodeR* build_value(size_t idx,
                             const std::vector<uint8_t>& nib,
                             const evmc::bytes32& pos_hash);
    const NodeR* update_value(size_t idx,
                              const std::vector<uint8_t>& nib);

    const NodeR* cached_at(size_t idx) const noexcept { return &leaf_[idx].cached; }
    const evmc::bytes32& pos_hash_at(size_t idx) const noexcept { return leaf_[idx].pos_hash; }

    // Set by the new-root insert phase for a created slot (appended at
    // run-time, not via build_value).
    void set_pos_hash(size_t idx, const evmc::bytes32& pos_hash);

    // True iff the slot value did not change since block start.
    bool value_unchanged_at(size_t idx) const noexcept {
        return value_orig_at(idx) == value_at(idx);
    }

    // Look up the array index of (addr, position). Aborts the guest via
    // zeg::fatal if the slot isn't in the table — the guest is supposed
    // to have every state it touches in its private input, so a missing
    // slot is a hard input-completeness bug, not a recoverable case.
    size_t index_of(const evmc::address& addr,
                    const evmc::bytes32& position) const;

    // DBG: non-fataling probe — true iff (addr, position) is in the table.
    bool contains(const evmc::address& addr,
                  const evmc::bytes32& position) const noexcept;

    // ----- per-tx tracking (EIP-2929 warm/cold + EIP-2200 originals) -----
    //
    // When a tx first touches a slot, snapshot the current value into
    // `tx_original` and bump `last_tx_idx`. Idempotent within a tx.
    // Warm state IS journaled — but the journaling happens at the
    // caller (ZiskStateDB) via `Journal::log_storage_warm` BEFORE the
    // bump. The table layer is journal-free; the rollback path uses
    // `set_warm_at` (below) to restore a prior `last_tx_idx`, and the
    // `set_value_at` overload above to restore both the slot value and
    // warmth atomically. `tx_original` is not journaled — it's only
    // consulted when `last_tx_idx == current_tx_idx`, which the
    // restored `last_tx_idx` already gates correctly.
    void                 mark_touched_at(size_t idx, uint64_t tx_idx) noexcept;

    // True iff this slot was touched in tx `tx_idx` (= warm for it).
    bool                 is_warm_at(size_t idx, uint64_t tx_idx) const noexcept;

    // Read the raw `last_tx_idx` field — used by ZiskStateDB to
    // capture the pre-write value for the journal.
    uint64_t             last_tx_idx_at(size_t idx) const noexcept;

    // Unconditional setter for `last_tx_idx`. Used by the journal's
    // rollback path to restore the pre-write value (which may be
    // smaller than the current one — `mark_touched_at` only bumps up).
    void                 set_warm_at(size_t idx, uint64_t tx_idx) noexcept;

    // Value at the start of the tx that last touched this slot. Only
    // meaningful when `is_warm_at(idx, current_tx_idx) == true`.
    const evmc::bytes32& tx_original_at(size_t idx) const noexcept;

    uint64_t size() const noexcept { return originals_.size(); }

    // All storage indices belonging to `addr`, in table order. Built once
    // at construction. Used by SELFDESTRUCT (EIP-6780 full-destroy) to
    // zero every slot of a same-tx-created account without scanning or
    // assuming any particular table sort order. Returns a reference to an
    // empty vector when the address owns no slots.
    const std::vector<size_t>& slots_of(const evmc::address& addr) const noexcept;

private:
    // View into one 88-byte record in `record_store_`. Layout:
    //   offset  size  field
    //        0   20   address       (raw bytes)
    //       20    4   pad           (keeps the record 8-aligned past address)
    //       24   32   position      (storage slot key)
    //       56   32   value         (slot value)
    //       88         end of record
    struct View {
        const uint8_t* data;

        static constexpr size_t kAddressOffset    = 0;
        static constexpr size_t kPositionOffset   = 24;
        static constexpr size_t kValueOffset      = 56;

        const evmc::address& address() const noexcept {
            return *reinterpret_cast<const evmc::address*>(data + kAddressOffset);
        }
        const evmc::bytes32& position() const noexcept {
            return *reinterpret_cast<const evmc::bytes32*>(data + kPositionOffset);
        }
        const evmc::bytes32& value() const noexcept {
            return *reinterpret_cast<const evmc::bytes32*>(data + kValueOffset);
        }
    };

    // Per-slot mutation slot. The slot value is fetched from `View`
    // unless `dirty` is set, in which case `value` here wins.
    //
    // `last_tx_idx` / `tx_original` track EIP-2929 warm state and
    // EIP-2200 per-tx-original: on the first touch in a tx,
    // `mark_touched_at` snapshots the slot's current value into
    // `tx_original` and bumps `last_tx_idx` to the tx counter.
    // `last_tx_idx` IS journaled via Journal::log_storage_warm so
    // a reverted frame restores the prior (possibly cold) value.
    // `tx_original` is not journaled — it's only consulted when
    // `last_tx_idx == current_tx_idx`, which the journal restores.
    // `last_tx_idx == 0` is the never-touched sentinel; the tx
    // counter starts at 1.
    struct Mods {
        bool          dirty : 1   = false;
        evmc::bytes32 value{};
        uint64_t      last_tx_idx = 0;
        evmc::bytes32 tx_original{};
    };

    // Composite map key: 20-byte address + 32-byte slot key. Trivially
    // copyable, no internal padding (both members are uint8_t arrays).
    struct Key {
        evmc::address address;
        evmc::bytes32 position;
    };
    static_assert(sizeof(Key) == 20 + 32, "Key must be tightly packed");

    // Hash: XOR the lowest 8 bytes of address and position. Both halves
    // are high-entropy big-endian quantities, so XOR-ing their LSB ends
    // produces a good distribution with one byte-fetch from each.
    struct KeyHash {
        size_t operator()(const Key& k) const noexcept {
            uint64_t a;
            std::memcpy(&a, k.address.bytes  + sizeof(k.address.bytes)  - 8, 8);
            uint64_t p;
            std::memcpy(&p, k.position.bytes + sizeof(k.position.bytes) - 8, 8);
            return static_cast<size_t>(a ^ p);
        }
    };
    struct KeyEq {
        bool operator()(const Key& x, const Key& y) const noexcept {
            return std::memcmp(&x, &y, sizeof(x)) == 0;
        }
    };

    // Address-only hash/eq for the per-account slot-index map. Addresses
    // are high-entropy, so the first 8 bytes make a good hash (same
    // rationale as Accounts::AddressHash).
    struct AddressHash {
        size_t operator()(const evmc::address& a) const noexcept {
            uint64_t v;
            std::memcpy(&v, a.bytes, sizeof(v));
            return static_cast<size_t>(v);
        }
    };
    struct AddressEq {
        bool operator()(const evmc::address& x, const evmc::address& y) const noexcept {
            return std::memcmp(x.bytes, y.bytes, sizeof(x.bytes)) == 0;
        }
    };

    // Per-row storage-trie leaf cache (parallel to `originals_`).
    struct LeafCache {
        NodeR         cached{};    // storage-leaf NodeR result
        evmc::bytes32 pos_hash{};  // keccak(position) — for the leaf path
    };

    // Owned backing buffer for the original records. Pre-sized exactly by
    // `reserve`; never reallocated, so `View` pointers stay valid.
    std::vector<uint8_t> record_store_;
    uint64_t             capacity_ = 0;

    std::vector<View>      originals_;
    std::vector<Mods>      mods_;
    std::vector<LeafCache> leaf_;
    std::unordered_map<Key, size_t, KeyHash, KeyEq> index_;
    // address -> its storage indices (see slots_of).
    std::unordered_map<evmc::address, std::vector<size_t>, AddressHash, AddressEq>
        addr_slots_;
};

} // namespace zeg

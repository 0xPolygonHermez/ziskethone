// TransientStorage — EIP-1153 transient-storage map (TLOAD/TSTORE).
//
// Unlike `Storages` (whose witness is fixed by the prover and indexed
// at construction), transient storage is fully dynamic: any
// (address, position) pair can be written without prior declaration,
// and the entire map is **reset at the start of every EVM frame** (each
// tx, each system call). Writes are journaled so revert restores them.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <optional>
#include <unordered_map>

#include <evmc/evmc.hpp>

#include "zeg/seeded_hash.hpp"
#include "zeg/tx_arena.hpp"

namespace zeg {

class TransientStorage {
public:
    // `seed` keys `map_` with the per-run universal hash
    // (zeg/seeded_hash.hpp); it must outlive the object.
    explicit TransientStorage(const zeg::HashSeed& seed)
        : seed_(&seed) { init(); }

    // Slot value at (addr, position); zero if not set.
    evmc::bytes32 get(const evmc::address& addr,
                      const evmc::bytes32& position) const noexcept;

    // Snapshot of the pre-write state, returned so the caller can
    // pass it to `Journal::log_transient` for revert.
    struct PreviousState {
        bool          was_present;
        evmc::bytes32 value;   // valid iff was_present
    };

    // Set the slot's value and return what was there before.
    PreviousState set(const evmc::address& addr,
                      const evmc::bytes32& position,
                      const evmc::bytes32& value);

    // Restore the slot to its pre-set state. Called by the Journal
    // when rolling back. `was_present == false` means erase the entry.
    void restore(const evmc::address& addr,
                 const evmc::bytes32& position,
                 bool                 was_present,
                 const evmc::bytes32& old_value);

    // Clear every entry. Called at the start of each EVM frame (tx
    // or system call) per EIP-1153.
    void reset() noexcept { release(); init(); }

    // reset() in two halves around zeg::tx_arena_reset(): release()
    // destroys the map (its nodes and buckets are in the tx arena), init()
    // builds an empty one, which already allocates its first buckets. So
    // at a tx start: release(), tx_arena_reset(), init(); no map may be
    // used in between. init() starts from the previous map's bucket count
    // (capped), as clear() would keep it, so a TSTORE-heavy tx doesn't
    // rehash its way up again.
    void release() noexcept {
        buckets_hint_ = std::min(map_->bucket_count(), kMaxBucketsHint);
        map_.reset();
    }
    void init() { map_.emplace(buckets_hint_, KeyHash{seed_}, KeyEq{}); }

    size_t size() const noexcept { return map_->size(); }

private:
    struct Key {
        evmc::address address;
        evmc::bytes32 position;
    };
    // KeyHash reads the whole struct; no padding must creep in, or equal keys
    // (compared field-wise by KeyEq) could hash differently.
    static_assert(sizeof(Key) == 20 + 32, "TransientStorage::Key must have no padding");
    struct KeyHash {
        // Seeded universal hash over the whole 52-byte Key — same rationale
        // as the persistent Storages class. See zeg/seeded_hash.hpp.
        const zeg::HashSeed* s_ = nullptr;
        size_t operator()(const Key& k) const noexcept {
            return static_cast<size_t>(zeg::hash_bytes(*s_, &k, sizeof(k)));
        }
    };
    struct KeyEq {
        bool operator()(const Key& x, const Key& y) const noexcept {
            return std::memcmp(x.address.bytes,  y.address.bytes,  sizeof(x.address.bytes))  == 0
                && std::memcmp(x.position.bytes, y.position.bytes, sizeof(x.position.bytes)) == 0;
        }
    };

    // Per-tx state, so its nodes live in the tx arena (zeg/tx_arena.hpp).
    using Map = std::unordered_map<Key, evmc::bytes32, KeyHash, KeyEq,
                                   TxArenaAllocator<std::pair<const Key, evmc::bytes32>>>;
    const zeg::HashSeed* seed_;
    std::optional<Map>   map_;   // empty only between release() and init()
    static constexpr size_t kMaxBucketsHint = size_t{1} << 17;
    size_t buckets_hint_ = 0;
};

} // namespace zeg

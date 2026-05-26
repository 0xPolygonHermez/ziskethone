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
#include <unordered_map>

#include <evmc/evmc.hpp>

namespace zeg {

class TransientStorage {
public:
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
    void reset() noexcept;

    size_t size() const noexcept { return map_.size(); }

private:
    struct Key {
        evmc::address address;
        evmc::bytes32 position;
    };
    struct KeyHash {
        size_t operator()(const Key& k) const noexcept {
            // Both halves are high-entropy; XOR the low 8 bytes of
            // each — same trick the persistent Storages class uses.
            uint64_t a, p;
            std::memcpy(&a, k.address.bytes  + sizeof(k.address.bytes)  - 8, 8);
            std::memcpy(&p, k.position.bytes + sizeof(k.position.bytes) - 8, 8);
            return static_cast<size_t>(a ^ p);
        }
    };
    struct KeyEq {
        bool operator()(const Key& x, const Key& y) const noexcept {
            return std::memcmp(x.address.bytes,  y.address.bytes,  sizeof(x.address.bytes))  == 0
                && std::memcmp(x.position.bytes, y.position.bytes, sizeof(x.position.bytes)) == 0;
        }
    };

    std::unordered_map<Key, evmc::bytes32, KeyHash, KeyEq> map_;
};

} // namespace zeg

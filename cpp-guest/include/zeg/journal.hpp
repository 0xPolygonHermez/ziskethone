// Journal — undo log for the ZisK Ethereum guest's state mutations.
//
// EVM execution is reentrant: every CALL / STATICCALL / DELEGATECALL /
// CREATE introduces a new frame whose state writes must be discarded if
// the frame reverts. We track every write in a single stack and let the
// caller checkpoint-and-rollback to roll back a frame's worth of writes.
//
// The stack mixes two kinds of entries:
//   * Checkpoint markers — placeholders pushed when a new frame begins.
//   * Write records      — one per nonce/balance/codeHash/storage write,
//                          capturing the value the field had BEFORE the
//                          write so it can be restored on rollback.
//
// Rollback pops entries from the top, applying each write record's
// `old_value` back to Accounts/Storages, until (and including) the
// requested checkpoint marker.

#pragma once

#include <cstdint>
#include <variant>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg {

// Forward declarations — the cpp pulls in the full headers.
class Accounts;
class Storages;
class TransientStorage;

class Journal {
public:
    // Opaque handle returned by `checkpoint()`; pass to `rollback()` to
    // undo every write performed since the matching checkpoint() call.
    using Checkpoint = size_t;

    // Push a checkpoint marker onto the stack and return its position.
    Checkpoint checkpoint();

    // Record the pre-write value of one mutable field. Call BEFORE the
    // corresponding write hits the Accounts/Storages tables. The `idx`
    // is the row index into the corresponding table — keeps the entry
    // small (8 B instead of 20 + maybe 32 for address + position).
    void log_nonce    (size_t idx, uint64_t                old_value);
    void log_balance  (size_t idx, const evmc::uint256be&  old_value);
    void log_code_hash(size_t idx, const evmc::bytes32&    old_value);
    void log_storage  (size_t idx, const evmc::bytes32&    old_value);

    // EIP-1153 transient storage. Unlike persistent storage, the
    // transient map is dynamic — there's no fixed index for a slot —
    // so the entry carries the full (address, position) key plus a
    // `was_present` flag indicating whether the slot existed before
    // this write (so rollback knows whether to `restore` to a value
    // or erase the entry).
    void log_transient(const evmc::address&  address,
                       const evmc::bytes32&  position,
                       bool                  was_present,
                       const evmc::bytes32&  old_value);

    // Pop every entry above `cp` (and the checkpoint marker itself),
    // applying each write record's old_value to `accounts` /
    // `storages` / `transient` in reverse order. Aborts via zeg::fatal
    // if `cp` does not refer to a valid checkpoint marker.
    void rollback(Checkpoint        cp,
                  Accounts&         accounts,
                  Storages&         storages,
                  TransientStorage& transient);

    // Stack depth (checkpoints + write records).
    size_t size() const noexcept { return entries_.size(); }

private:
    struct CheckpointMarker {};
    struct NonceEntry    { size_t idx; uint64_t                old_value; };
    struct BalanceEntry  { size_t idx; evmc::uint256be         old_value; };
    struct CodeHashEntry { size_t idx; evmc::bytes32           old_value; };
    struct StorageEntry  { size_t idx; evmc::bytes32           old_value; };
    struct TransientEntry {
        evmc::address  address;
        evmc::bytes32  position;
        bool           was_present;
        evmc::bytes32  old_value;   // valid iff was_present
    };

    using Entry = std::variant<
        CheckpointMarker,
        NonceEntry,
        BalanceEntry,
        CodeHashEntry,
        StorageEntry,
        TransientEntry>;

    std::vector<Entry> entries_;
};

} // namespace zeg

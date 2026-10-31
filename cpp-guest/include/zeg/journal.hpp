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

#include <algorithm>
#include <cstdint>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <evmc/evmc.hpp>

#include "zeg/chunked_vector.hpp"
#include "zeg/tx_arena.hpp"
#include "zeg/warm_keys.hpp"

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

    // Record the pre-write value of one mutable field PLUS the
    // pre-write `last_tx_idx`. Call BEFORE the corresponding write
    // hits the Accounts/Storages tables. Capturing the tx_idx
    // alongside the value lets rollback restore both atomically
    // through the matching `set_*_at(idx, value, tx_idx)` setter —
    // no separate warm entry is needed for the same operation. The
    // `idx` is the row index into the corresponding table.
    void log_nonce    (size_t idx, uint64_t                old_value,
                       uint64_t old_last_tx_idx);
    void log_balance  (size_t idx, const evmc::uint256be&  old_value,
                       uint64_t old_last_tx_idx);
    void log_code_hash(size_t idx, const evmc::bytes32&    old_value,
                       uint64_t old_last_tx_idx);
    void log_storage  (size_t idx, const evmc::bytes32&    old_value,
                       uint64_t old_last_tx_idx);

    // EIP-2929 warm/cold state journaling for pure-access operations
    // (access_account / access_storage that didn't also write a value).
    // Without this the warm state would leak across reverted frames and
    // subsequent SLOADs/CALLs would be charged warm instead of cold —
    // a per-tx gas undercharge. For accesses paired with a value write,
    // use the matching log_balance/nonce/code_hash/storage above
    // (they capture both old_value AND old_last_tx_idx).
    void log_account_warm(size_t idx, uint64_t old_last_tx_idx);
    void log_storage_warm(size_t idx, uint64_t old_last_tx_idx);

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

    // Warmth of a key with no table row (see `WarmKeys`): the pre-access
    // `last_tx_idx` (0 = the key wasn't there, so rollback removes it).
    void log_warm_key_account(const evmc::address& address, uint64_t old_last_tx_idx);
    void log_warm_key_slot(const evmc::address& address, const evmc::bytes32& position,
                           uint64_t old_last_tx_idx);

    // Per Yellow Paper, SELFDESTRUCT registers the account for
    // deletion-at-end-of-tx rather than wiping it immediately. cpp-
    // guest tracks this via `ZiskStateDB::pending_destruct_`. The
    // journal entry lets a reverted SELFDESTRUCT frame un-register
    // the account. `was_already_present` distinguishes "I inserted
    // this row, rollback erases it" from "the row was already there
    // from a prior SELFDESTRUCT in this tx that didn't revert,
    // rollback leaves it alone".
    void log_pending_destruct(size_t idx, bool was_already_present);

    // Pop every entry above `cp` (and the checkpoint marker itself),
    // applying each write record's old_value to `accounts` /
    // `storages` / `warm_keys` / `transient` in reverse order.
    // `pending_destruct` is the SELFDESTRUCT-pending-at-end-of-tx set
    // owned by ZiskStateDB; PendingDestructEntry rollback removes
    // entries from it. Aborts via zeg::fatal if `cp` does not refer
    // to a valid checkpoint marker.
    void rollback(Checkpoint                  cp,
                  Accounts&                   accounts,
                  Storages&                   storages,
                  WarmKeys&                   warm_keys,
                  TransientStorage&           transient,
                  std::unordered_set<size_t>& pending_destruct);

    // Stack depth (checkpoints + write records).
    size_t size() const noexcept { return entries_.size(); }

    // Drop every entry AND the storage (in the tx arena, see
    // zeg/tx_arena.hpp). Called at each transaction start, when no
    // checkpoint is outstanding: rollbacks never reach a previous tx.
    void release() noexcept { entries_.release(); }

private:
    struct CheckpointMarker {};
    struct NonceEntry    { size_t idx; uint64_t        old_value;
                                       uint64_t        old_last_tx_idx; };
    struct BalanceEntry  { size_t idx; evmc::uint256be old_value;
                                       uint64_t        old_last_tx_idx; };
    struct CodeHashEntry { size_t idx; evmc::bytes32   old_value;
                                       uint64_t        old_last_tx_idx; };
    struct StorageEntry  { size_t idx; evmc::bytes32   old_value;
                                       uint64_t        old_last_tx_idx; };
    struct AccountWarmEntry { size_t idx; uint64_t     old_last_tx_idx; };
    struct StorageWarmEntry { size_t idx; uint64_t     old_last_tx_idx; };
    struct TransientEntry {
        evmc::address  address;
        evmc::bytes32  position;
        bool           was_present;
        evmc::bytes32  old_value;   // valid iff was_present
    };
    struct WarmKeyAccountEntry {
        evmc::address address;
        uint64_t      old_last_tx_idx;
    };
    struct WarmKeySlotEntry {
        evmc::address address;
        evmc::bytes32 position;
        uint64_t      old_last_tx_idx;
    };
    struct PendingDestructEntry {
        size_t idx;
        bool   was_already_present;
    };

    using Entry = std::variant<
        CheckpointMarker,
        NonceEntry,
        BalanceEntry,
        CodeHashEntry,
        StorageEntry,
        AccountWarmEntry,
        StorageWarmEntry,
        TransientEntry,
        WarmKeyAccountEntry,
        WarmKeySlotEntry,
        PendingDestructEntry>;

    // Chunks, not a doubling vector: a transaction can log one entry per
    // 100 gas (TSTORE), and the buffers a std::vector outgrew stayed in the
    // arena until the transaction ended (~25 MB more in one 2^24-gas TSTORE
    // loop). See zeg/chunked_vector.hpp.
    ChunkedVector<Entry, 256, 4096, TxArenaAllocator<Entry>> entries_;

    // Per-entry arena cost the journal budget relies on (HEAP_BUDGET.md); a
    // layout change means updating scripts/heap_gate/sites.tsv.
    static_assert(sizeof(Entry) == 96);  // heap-budget: journal-entry
};

} // namespace zeg

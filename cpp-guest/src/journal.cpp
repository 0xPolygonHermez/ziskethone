#include "zeg/journal.hpp"

#include <type_traits>
#include <utility>

#include "zeg/accounts.hpp"
#include "zeg/dynamic_storage.hpp"
#include "zeg/fatal.hpp"
#include "zeg/storages.hpp"
#include "zeg/transient_storage.hpp"

namespace zeg {

Journal::Checkpoint Journal::checkpoint() {
    entries_.emplace_back(CheckpointMarker{});
    return entries_.size() - 1;
}

void Journal::log_nonce(size_t idx, uint64_t old_value,
                        uint64_t old_last_tx_idx) {
    entries_.emplace_back(NonceEntry{idx, old_value, old_last_tx_idx});
}

void Journal::log_balance(size_t idx, const evmc::uint256be& old_value,
                          uint64_t old_last_tx_idx) {
    entries_.emplace_back(BalanceEntry{idx, old_value, old_last_tx_idx});
}

void Journal::log_code_hash(size_t idx, const evmc::bytes32& old_value,
                            uint64_t old_last_tx_idx) {
    entries_.emplace_back(CodeHashEntry{idx, old_value, old_last_tx_idx});
}

void Journal::log_storage(size_t idx, const evmc::bytes32& old_value,
                          uint64_t old_last_tx_idx) {
    entries_.emplace_back(StorageEntry{idx, old_value, old_last_tx_idx});
}

void Journal::log_account_warm(size_t idx, uint64_t old_last_tx_idx) {
    entries_.emplace_back(AccountWarmEntry{idx, old_last_tx_idx});
}

void Journal::log_storage_warm(size_t idx, uint64_t old_last_tx_idx) {
    entries_.emplace_back(StorageWarmEntry{idx, old_last_tx_idx});
}

void Journal::log_transient(const evmc::address&  address,
                            const evmc::bytes32&  position,
                            bool                  was_present,
                            const evmc::bytes32&  old_value) {
    entries_.emplace_back(TransientEntry{address, position, was_present, old_value});
}

void Journal::log_dyn_storage(const evmc::address&  address,
                              const evmc::bytes32&  position,
                              bool                  was_present,
                              const evmc::bytes32&  old_value,
                              uint64_t              old_last_tx_idx) {
    entries_.emplace_back(DynStorageEntry{address, position, was_present,
                                          old_value, old_last_tx_idx});
}

void Journal::log_dyn_storage_warm(const evmc::address&  address,
                                   const evmc::bytes32&  position,
                                   uint64_t              old_last_tx_idx) {
    entries_.emplace_back(DynStorageWarmEntry{address, position, old_last_tx_idx});
}

void Journal::log_dyn_account_erase(const evmc::address&        address,
                                    DynamicStorage::Snapshot&&  snapshot) {
    entries_.emplace_back(DynAccountEraseEntry{address, std::move(snapshot)});
}

void Journal::log_pending_destruct(size_t idx, bool was_already_present) {
    entries_.emplace_back(PendingDestructEntry{idx, was_already_present});
}

void Journal::rollback(Checkpoint                  cp,
                       Accounts&                   accounts,
                       Storages&                   storages,
                       DynamicStorage&             dynamic_storage,
                       TransientStorage&           transient,
                       std::unordered_set<size_t>& pending_destruct) {
    if (cp >= entries_.size()
        || !std::holds_alternative<CheckpointMarker>(entries_[cp])) {
        fatal("Journal::rollback: invalid checkpoint");
    }
    while (entries_.size() > cp) {
        // std::visit gets `auto&` so we can move out of owning entries
        // (specifically `DynAccountEraseEntry::snapshot`).
        std::visit([&](auto& e) {
            using T = std::decay_t<decltype(e)>;
            if constexpr (std::is_same_v<T, NonceEntry>) {
                accounts.set_nonce_at(e.idx, e.old_value, e.old_last_tx_idx);
            } else if constexpr (std::is_same_v<T, BalanceEntry>) {
                accounts.set_balance_at(e.idx, e.old_value, e.old_last_tx_idx);
            } else if constexpr (std::is_same_v<T, CodeHashEntry>) {
                accounts.set_code_hash_at(e.idx, e.old_value, e.old_last_tx_idx);
            } else if constexpr (std::is_same_v<T, StorageEntry>) {
                storages.set_value_at(e.idx, e.old_value, e.old_last_tx_idx);
            } else if constexpr (std::is_same_v<T, AccountWarmEntry>) {
                accounts.set_warm_at(e.idx, e.old_last_tx_idx);
            } else if constexpr (std::is_same_v<T, StorageWarmEntry>) {
                storages.set_warm_at(e.idx, e.old_last_tx_idx);
            } else if constexpr (std::is_same_v<T, TransientEntry>) {
                transient.restore(e.address, e.position,
                                  e.was_present, e.old_value);
            } else if constexpr (std::is_same_v<T, DynStorageEntry>) {
                if (e.was_present) {
                    dynamic_storage.restore_slot(e.address, e.position,
                                                 e.old_value, e.old_last_tx_idx);
                } else {
                    dynamic_storage.unset_slot(e.address, e.position);
                }
            } else if constexpr (std::is_same_v<T, DynStorageWarmEntry>) {
                dynamic_storage.set_warm(e.address, e.position, e.old_last_tx_idx);
            } else if constexpr (std::is_same_v<T, DynAccountEraseEntry>) {
                dynamic_storage.restore_account(e.address, std::move(e.snapshot));
            } else if constexpr (std::is_same_v<T, PendingDestructEntry>) {
                // If THIS log entry was the one that inserted the
                // idx, remove it on rollback. If it was already
                // present from a prior unreverted SELFDESTRUCT in
                // this tx, leave it alone.
                if (!e.was_already_present) {
                    pending_destruct.erase(e.idx);
                }
            }
            // CheckpointMarker: nothing to undo, just pop below.
        }, entries_.back());
        entries_.pop_back();
    }
}

} // namespace zeg

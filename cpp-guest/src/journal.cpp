#include "zeg/journal.hpp"

#include <type_traits>

#include "zeg/accounts.hpp"
#include "zeg/fatal.hpp"
#include "zeg/storages.hpp"
#include "zeg/transient_storage.hpp"

namespace zeg {

Journal::Checkpoint Journal::checkpoint() {
    entries_.emplace_back(CheckpointMarker{});
    return entries_.size() - 1;
}

void Journal::log_nonce(size_t idx, uint64_t old_value) {
    entries_.emplace_back(NonceEntry{idx, old_value});
}

void Journal::log_balance(size_t idx, const evmc::uint256be& old_value) {
    entries_.emplace_back(BalanceEntry{idx, old_value});
}

void Journal::log_code_hash(size_t idx, const evmc::bytes32& old_value) {
    entries_.emplace_back(CodeHashEntry{idx, old_value});
}

void Journal::log_storage(size_t idx, const evmc::bytes32& old_value) {
    entries_.emplace_back(StorageEntry{idx, old_value});
}

void Journal::log_transient(const evmc::address&  address,
                            const evmc::bytes32&  position,
                            bool                  was_present,
                            const evmc::bytes32&  old_value) {
    entries_.emplace_back(TransientEntry{address, position, was_present, old_value});
}

void Journal::rollback(Checkpoint        cp,
                       Accounts&         accounts,
                       Storages&         storages,
                       TransientStorage& transient) {
    if (cp >= entries_.size()
        || !std::holds_alternative<CheckpointMarker>(entries_[cp])) {
        fatal("Journal::rollback: invalid checkpoint");
    }
    while (entries_.size() > cp) {
        std::visit([&](const auto& e) {
            using T = std::decay_t<decltype(e)>;
            if constexpr (std::is_same_v<T, NonceEntry>) {
                accounts.set_nonce_at(e.idx, e.old_value);
            } else if constexpr (std::is_same_v<T, BalanceEntry>) {
                accounts.set_balance_at(e.idx, e.old_value);
            } else if constexpr (std::is_same_v<T, CodeHashEntry>) {
                accounts.set_code_hash_at(e.idx, e.old_value);
            } else if constexpr (std::is_same_v<T, StorageEntry>) {
                storages.set_value_at(e.idx, e.old_value);
            } else if constexpr (std::is_same_v<T, TransientEntry>) {
                transient.restore(e.address, e.position,
                                  e.was_present, e.old_value);
            }
            // CheckpointMarker: nothing to undo, just pop below.
        }, entries_.back());
        entries_.pop_back();
    }
}

} // namespace zeg

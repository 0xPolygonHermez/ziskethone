#include "zeg/dynamic_storage.hpp"

namespace zeg {

bool DynamicStorage::contains(const evmc::address& addr) const noexcept {
    return entries_.find(addr) != entries_.end();
}

bool DynamicStorage::contains(const evmc::address& addr,
                              const evmc::bytes32& pos) const noexcept {
    const auto outer = entries_.find(addr);
    if (outer == entries_.end()) return false;
    return outer->second.find(pos) != outer->second.end();
}

evmc::bytes32 DynamicStorage::value(const evmc::address& addr,
                                    const evmc::bytes32& pos) const noexcept {
    const auto outer = entries_.find(addr);
    if (outer == entries_.end()) return evmc::bytes32{};
    const auto inner = outer->second.find(pos);
    if (inner == outer->second.end()) return evmc::bytes32{};
    return inner->second.value;
}

evmc::bytes32 DynamicStorage::tx_original(const evmc::address& addr,
                                          const evmc::bytes32& pos,
                                          uint64_t              tx_idx) const noexcept {
    const auto outer = entries_.find(addr);
    if (outer == entries_.end()) return evmc::bytes32{};
    const auto inner = outer->second.find(pos);
    if (inner == outer->second.end()) return evmc::bytes32{};
    // The snapshot only means "tx_idx's original" when the slot was
    // touched in this tx; otherwise the implicit block-original (0)
    // is the answer.
    if (inner->second.last_tx_idx != tx_idx) return evmc::bytes32{};
    return inner->second.tx_original;
}

bool DynamicStorage::is_warm(const evmc::address& addr,
                             const evmc::bytes32& pos,
                             uint64_t              tx_idx) const noexcept {
    const auto outer = entries_.find(addr);
    if (outer == entries_.end()) return false;
    const auto inner = outer->second.find(pos);
    if (inner == outer->second.end()) return false;
    return inner->second.last_tx_idx == tx_idx;
}

uint64_t DynamicStorage::last_tx_idx(const evmc::address& addr,
                                     const evmc::bytes32& pos) const noexcept {
    const auto outer = entries_.find(addr);
    if (outer == entries_.end()) return 0;
    const auto inner = outer->second.find(pos);
    if (inner == outer->second.end()) return 0;
    return inner->second.last_tx_idx;
}

bool DynamicStorage::set_value(const evmc::address& addr,
                               const evmc::bytes32& pos,
                               const evmc::bytes32& v,
                               uint64_t              tx_idx) {
    auto& inner = entries_[addr];
    auto [it, inserted] = inner.try_emplace(pos);
    it->second.value       = v;
    it->second.last_tx_idx = tx_idx;
    // tx_original is set by mark_touched (which evmone calls via
    // access_storage BEFORE the first SSTORE on Berlin+). If somehow
    // we reach set_value first (cold first-write), tx_original stays
    // at its default zero value — correct for a fresh-account slot
    // whose pre-tx original is 0.
    return inserted;
}

void DynamicStorage::mark_touched(const evmc::address& addr,
                                  const evmc::bytes32& pos,
                                  uint64_t              tx_idx) {
    auto& inner = entries_[addr];
    auto& slot = inner[pos]; // auto-inserts with default Slot{}
    if (tx_idx > slot.last_tx_idx) {
        // First touch in this tx — snapshot the current value
        // (block-original 0 if absent, else slot.value) into
        // tx_original for EIP-2200 gas accounting.
        slot.tx_original = slot.value;
        slot.last_tx_idx = tx_idx;
    }
}

void DynamicStorage::restore_slot(const evmc::address& addr,
                                  const evmc::bytes32& pos,
                                  const evmc::bytes32& v,
                                  uint64_t              last_tx_idx) {
    auto& inner = entries_[addr];
    auto& slot = inner[pos];
    slot.value       = v;
    slot.last_tx_idx = last_tx_idx;
    // tx_original is not journaled (mirror of Storages convention) —
    // it's only consulted when last_tx_idx == current_tx_idx, which
    // we just restored.
}

void DynamicStorage::unset_slot(const evmc::address& addr,
                                const evmc::bytes32& pos) {
    const auto outer = entries_.find(addr);
    if (outer == entries_.end()) return;
    outer->second.erase(pos);
    if (outer->second.empty()) {
        entries_.erase(outer);
    }
}

void DynamicStorage::set_warm(const evmc::address& addr,
                              const evmc::bytes32& pos,
                              uint64_t              last_tx_idx) {
    auto& inner = entries_[addr];
    auto& slot = inner[pos];
    slot.last_tx_idx = last_tx_idx;
}

DynamicStorage::Snapshot DynamicStorage::erase_account(const evmc::address& addr) {
    Snapshot snap;
    const auto outer = entries_.find(addr);
    if (outer == entries_.end()) return snap;
    snap.reserve(outer->second.size());
    for (auto& kv : outer->second) {
        snap.emplace_back(kv.first, std::move(kv.second));
    }
    entries_.erase(outer);
    return snap;
}

void DynamicStorage::restore_account(const evmc::address& addr,
                                     Snapshot&& snap) {
    auto& inner = entries_[addr];
    for (auto& [pos, slot] : snap) {
        inner.insert_or_assign(pos, std::move(slot));
    }
}

} // namespace zeg

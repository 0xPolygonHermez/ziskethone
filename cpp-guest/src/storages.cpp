#include "zeg/storages.hpp"

#include <cstdio>

#include "zeg/fatal.hpp"
#include "zeg/stream.hpp"

namespace zeg {

void Storages::reserve(uint64_t count) {
    record_store_.assign(count * kRecordSize, 0);
    capacity_ = count;
    originals_.reserve(count);
    mods_.reserve(count);
    index_.reserve(count);
}

size_t Storages::append(const evmc::address& address,
                        const evmc::bytes32& position,
                        const evmc::bytes32& value) {
    const size_t idx = originals_.size();
    if (idx >= capacity_) {
        fatal("Storages::append: more rows than reserve() allowed (numberOfStorages overflow)");
    }
    uint8_t* rec = record_store_.data() + idx * kRecordSize;
    std::memcpy(rec + View::kAddressOffset,  address.bytes,  sizeof(address.bytes));
    std::memcpy(rec + View::kPositionOffset, position.bytes, sizeof(position.bytes));
    std::memcpy(rec + View::kValueOffset,    value.bytes,    sizeof(value.bytes));
    originals_.push_back(View{rec});
    mods_.push_back(Mods{});
    index_.emplace(Key{address, position}, idx);
    addr_slots_[address].push_back(idx);
    return idx;
}

const std::vector<size_t>& Storages::slots_of(
        const evmc::address& addr) const noexcept {
    static const std::vector<size_t> kEmpty;
    const auto it = addr_slots_.find(addr);
    return it == addr_slots_.end() ? kEmpty : it->second;
}

size_t Storages::index_of(const evmc::address& addr,
                          const evmc::bytes32& position) const {
    const auto it = index_.find(Key{addr, position});
    if (it == index_.end()) {
        std::fprintf(stderr, "DBG missing storage slot addr=0x");
        for (int i = 0; i < 20; ++i) std::fprintf(stderr, "%02x", addr.bytes[i]);
        std::fprintf(stderr, " pos=0x");
        for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", position.bytes[i]);
        std::fprintf(stderr, "\n");
        fatal("Storages::index_of: (address, position) not present in the table");
    }
    return it->second;
}

bool Storages::contains(const evmc::address& addr,
                        const evmc::bytes32& position) const noexcept {
    return index_.find(Key{addr, position}) != index_.end();
}

evmc::bytes32 Storages::value(const evmc::address& addr,
                              const evmc::bytes32& position,
                              uint64_t              tx_idx) {
    const size_t i = index_of(addr, position);
    mark_touched_at(i, tx_idx);
    return mods_[i].dirty ? mods_[i].value : originals_[i].value();
}

void Storages::set_value(const evmc::address& addr,
                         const evmc::bytes32& position,
                         const evmc::bytes32& v,
                         uint64_t              tx_idx) {
    set_value_at(index_of(addr, position), v, tx_idx);
}

void Storages::set_value_at(size_t idx, const evmc::bytes32& v, uint64_t tx_idx) {
    auto& m = mods_[idx];
    m.value       = v;
    m.dirty       = true;
    m.last_tx_idx = tx_idx;
}

void Storages::mark_touched_at(size_t idx, uint64_t tx_idx) noexcept {
    auto& m = mods_[idx];
    if (tx_idx > m.last_tx_idx) {
        m.last_tx_idx = tx_idx;
        // Snapshot current value (dirty new if any, else block-original).
        m.tx_original = m.dirty ? m.value : originals_[idx].value();
    }
}

bool Storages::is_warm_at(size_t idx, uint64_t tx_idx) const noexcept {
    return mods_[idx].last_tx_idx == tx_idx;
}

uint64_t Storages::last_tx_idx_at(size_t idx) const noexcept {
    return mods_[idx].last_tx_idx;
}

void Storages::set_warm_at(size_t idx, uint64_t tx_idx) noexcept {
    // Unconditional: unlike `mark_touched_at`, this can step
    // `last_tx_idx` backward — used by the journal's rollback path
    // to restore the pre-write value.
    mods_[idx].last_tx_idx = tx_idx;
}

const evmc::bytes32& Storages::tx_original_at(size_t idx) const noexcept {
    return mods_[idx].tx_original;
}

const evmc::address& Storages::address_at(size_t idx) const noexcept {
    return originals_[idx].address();
}

const evmc::bytes32& Storages::position_at(size_t idx) const noexcept {
    return originals_[idx].position();
}

evmc::bytes32 Storages::value_at(size_t idx) const noexcept {
    return mods_[idx].dirty ? mods_[idx].value : originals_[idx].value();
}

const evmc::bytes32& Storages::value_orig_at(size_t idx) const noexcept {
    return originals_[idx].value();
}

} // namespace zeg

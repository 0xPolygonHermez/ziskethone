#include "zeg/storages.hpp"

#include "zeg/fatal.hpp"
#include "zeg/stream.hpp"

namespace zeg {

Storages::Storages(const uint8_t*& cursor) {
    const uint64_t count   = read_u64_le(cursor);
    const uint8_t* records = cursor;
    originals_.reserve(count);
    mods_.resize(count);
    index_.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t* record = records + i * kRecordSize;
        originals_.push_back(View{record});
        const View& v = originals_.back();
        index_.emplace(Key{v.address(), v.position()}, i);
    }
    cursor += count * kRecordSize;
}

size_t Storages::index_of(const evmc::address& addr,
                          const evmc::bytes32& position) const {
    const auto it = index_.find(Key{addr, position});
    if (it == index_.end()) {
        fatal("Storages::index_of: (address, position) not present in the table");
    }
    return it->second;
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
    const size_t i = index_of(addr, position);
    mark_touched_at(i, tx_idx);
    set_value_at(i, v);
}

void Storages::set_value_at(size_t idx, const evmc::bytes32& v) {
    mods_[idx].value = v;
    mods_[idx].dirty = true;
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

bool Storages::is_read_only_at(size_t idx) const noexcept {
    return originals_[idx].is_read_only();
}

} // namespace zeg

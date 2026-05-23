#include "zeg/storages.hpp"

#include "zeg/fatal.hpp"

namespace zeg {

Storages::Storages(uint64_t count, const uint8_t* data) {
    originals_.reserve(count);
    mods_.resize(count);
    index_.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t* record = data + i * kRecordSize;
        originals_.push_back(View{record});
        const View& v = originals_.back();
        index_.emplace(Key{v.address(), v.position()}, i);
    }
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
                              const evmc::bytes32& position) const {
    const size_t i = index_of(addr, position);
    return mods_[i].dirty ? mods_[i].value : originals_[i].value();
}

void Storages::set_value(const evmc::address& addr,
                         const evmc::bytes32& position,
                         const evmc::bytes32& v) {
    set_value_at(index_of(addr, position), v);
}

void Storages::set_value_at(size_t idx, const evmc::bytes32& v) {
    mods_[idx].value = v;
    mods_[idx].dirty = true;
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

} // namespace zeg

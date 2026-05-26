#include "zeg/transient_storage.hpp"

namespace zeg {

evmc::bytes32 TransientStorage::get(const evmc::address& addr,
                                    const evmc::bytes32& position) const noexcept {
    const auto it = map_.find(Key{addr, position});
    return it == map_.end() ? evmc::bytes32{} : it->second;
}

TransientStorage::PreviousState
TransientStorage::set(const evmc::address& addr,
                      const evmc::bytes32& position,
                      const evmc::bytes32& value) {
    const Key k{addr, position};
    const auto it = map_.find(k);
    if (it == map_.end()) {
        map_.emplace(k, value);
        return {false, evmc::bytes32{}};
    }
    const auto old = it->second;
    it->second = value;
    return {true, old};
}

void TransientStorage::restore(const evmc::address& addr,
                               const evmc::bytes32& position,
                               bool                 was_present,
                               const evmc::bytes32& old_value) {
    const Key k{addr, position};
    if (was_present) {
        map_[k] = old_value;
    } else {
        map_.erase(k);
    }
}

void TransientStorage::reset() noexcept {
    map_.clear();
}

} // namespace zeg

// WarmKeys — EIP-2929 warmth of keys that have no table row.
//
// Every account and slot the block loads is a row of the Accounts / Storages
// tables (the input places an empty leaf for each one that doesn't exist), and
// any load of a key without a row halts. Warming is not a load: an EIP-2930
// access-list entry, the tx origin / coinbase / to, or an `access_account` /
// `access_storage` whose gas charge then fails need no state. Their warmth
// lives here, keyed by plaintext, with the same `last_tx_idx` convention as
// the tables (warm iff == the current tx counter; 0 = never touched).
// Journaled through `Journal::log_warm_key_*`.

#pragma once

#include <cstdint>
#include <cstring>
#include <unordered_map>

#include <evmc/evmc.hpp>

#include "zeg/seeded_hash.hpp"

namespace zeg {

class WarmKeys {
public:
    // `seed` keys both maps with the per-run universal hash
    // (zeg/seeded_hash.hpp) so author-grindable access-list keys cannot be
    // forced into one bucket; it must outlive the object.
    explicit WarmKeys(const zeg::HashSeed& seed)
        : accounts_(0, AddressHash{&seed})
        , slots_(0, KeyHash{&seed}) {}

    uint64_t account(const evmc::address& addr) const noexcept {
        const auto it = accounts_.find(addr);
        return it == accounts_.end() ? 0 : it->second;
    }
    void set_account(const evmc::address& addr, uint64_t tx_idx) {
        if (tx_idx == 0) {
            accounts_.erase(addr);
        } else {
            accounts_[addr] = tx_idx;
        }
    }

    uint64_t slot(const evmc::address& addr, const evmc::bytes32& key) const noexcept {
        const auto it = slots_.find(Key{addr, key});
        return it == slots_.end() ? 0 : it->second;
    }
    void set_slot(const evmc::address& addr, const evmc::bytes32& key, uint64_t tx_idx) {
        if (tx_idx == 0) {
            slots_.erase(Key{addr, key});
        } else {
            slots_[Key{addr, key}] = tx_idx;
        }
    }

private:
    struct AddressHash {
        const zeg::HashSeed* s_ = nullptr;
        size_t operator()(const evmc::address& a) const noexcept {
            return static_cast<size_t>(zeg::hash_bytes(*s_, a.bytes, sizeof(a.bytes)));
        }
    };
    struct Key {
        evmc::address address;
        uint32_t      pad = 0;
        evmc::bytes32 position;
        Key(const evmc::address& a, const evmc::bytes32& p) noexcept
            : address(a), position(p) {}
        bool operator==(const Key& o) const noexcept {
            return std::memcmp(this, &o, sizeof(Key)) == 0;
        }
    };
    static_assert(sizeof(Key) == 24 + 32, "Key must have no tail padding");
    struct KeyHash {
        const zeg::HashSeed* s_ = nullptr;
        size_t operator()(const Key& k) const noexcept {
            return static_cast<size_t>(zeg::hash_bytes(*s_, &k, sizeof(k)));
        }
    };

    std::unordered_map<evmc::address, uint64_t, AddressHash> accounts_;
    std::unordered_map<Key, uint64_t, KeyHash>               slots_;
};

} // namespace zeg

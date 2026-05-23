#include "zeg/accounts.hpp"

#include "zeg/fatal.hpp"

namespace zeg {

Accounts::Accounts(uint64_t count, const uint8_t* data) {
    originals_.reserve(count);
    mods_.resize(count);
    index_.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t* record = data + i * kRecordSize;
        originals_.push_back(View{record});
        index_.emplace(originals_.back().address(), i);
    }
}

size_t Accounts::index_of(const evmc::address& addr) const {
    const auto it = index_.find(addr);
    if (it == index_.end()) {
        fatal("Accounts::index_of: address not present in the table");
    }
    return it->second;
}

// ----- read accessors -----

evmc::uint256be Accounts::balance(const evmc::address& addr) const {
    const size_t i = index_of(addr);
    return mods_[i].balance_dirty ? mods_[i].balance : originals_[i].balance();
}

uint64_t Accounts::nonce(const evmc::address& addr) const {
    const size_t i = index_of(addr);
    return mods_[i].nonce_dirty ? mods_[i].nonce : originals_[i].nonce();
}

evmc::bytes32 Accounts::code_hash(const evmc::address& addr) const {
    const size_t i = index_of(addr);
    return mods_[i].code_hash_dirty ? mods_[i].code_hash : originals_[i].code_hash();
}

const evmc::address& Accounts::address_at(size_t idx) const noexcept {
    return originals_[idx].address();
}

evmc::uint256be Accounts::balance_at(size_t idx) const noexcept {
    return mods_[idx].balance_dirty ? mods_[idx].balance : originals_[idx].balance();
}

uint64_t Accounts::nonce_at(size_t idx) const noexcept {
    return mods_[idx].nonce_dirty ? mods_[idx].nonce : originals_[idx].nonce();
}

evmc::bytes32 Accounts::code_hash_at(size_t idx) const noexcept {
    return mods_[idx].code_hash_dirty ? mods_[idx].code_hash : originals_[idx].code_hash();
}

const evmc::bytes32& Accounts::storage_root_at(size_t idx) const noexcept {
    return originals_[idx].storage_root();
}

// ----- write accessors -----

void Accounts::set_balance(const evmc::address& addr, const evmc::uint256be& v) {
    set_balance_at(index_of(addr), v);
}

void Accounts::set_nonce(const evmc::address& addr, uint64_t v) {
    set_nonce_at(index_of(addr), v);
}

void Accounts::set_code_hash(const evmc::address& addr, const evmc::bytes32& v) {
    set_code_hash_at(index_of(addr), v);
}

void Accounts::set_balance_at(size_t idx, const evmc::uint256be& v) {
    mods_[idx].balance = v;
    mods_[idx].balance_dirty = true;
}

void Accounts::set_nonce_at(size_t idx, uint64_t v) {
    mods_[idx].nonce = v;
    mods_[idx].nonce_dirty = true;
}

void Accounts::set_code_hash_at(size_t idx, const evmc::bytes32& v) {
    mods_[idx].code_hash = v;
    mods_[idx].code_hash_dirty = true;
}

} // namespace zeg

#include "zeg/accounts.hpp"

#include "zeg/fatal.hpp"
#include "zeg/stream.hpp"

namespace zeg {

Accounts::Accounts(const uint8_t*& cursor) {
    const uint64_t count   = read_u64_le(cursor);
    const uint8_t* records = cursor;
    originals_.reserve(count);
    mods_.resize(count);
    index_.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t* record = records + i * kRecordSize;
        originals_.push_back(View{record});
        index_.emplace(originals_.back().address(), i);
    }
    cursor += count * kRecordSize;
}

size_t Accounts::index_of(const evmc::address& addr) const {
    const auto it = index_.find(addr);
    if (it == index_.end()) {
        fatal("Accounts::index_of: address not present in the table");
    }
    return it->second;
}

// ----- read accessors -----

evmc::uint256be Accounts::balance(const evmc::address& addr, uint64_t tx_idx) {
    const size_t i = index_of(addr);
    mark_touched_at(i, tx_idx);
    return mods_[i].balance_dirty ? mods_[i].balance : originals_[i].balance();
}

uint64_t Accounts::nonce(const evmc::address& addr, uint64_t tx_idx) {
    const size_t i = index_of(addr);
    mark_touched_at(i, tx_idx);
    return mods_[i].nonce_dirty ? mods_[i].nonce : originals_[i].nonce();
}

evmc::bytes32 Accounts::code_hash(const evmc::address& addr, uint64_t tx_idx) {
    const size_t i = index_of(addr);
    mark_touched_at(i, tx_idx);
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

const evmc::uint256be& Accounts::balance_orig_at(size_t idx) const noexcept {
    return originals_[idx].balance();
}

uint64_t Accounts::nonce_orig_at(size_t idx) const noexcept {
    return originals_[idx].nonce();
}

const evmc::bytes32& Accounts::code_hash_orig_at(size_t idx) const noexcept {
    return originals_[idx].code_hash();
}

bool Accounts::is_read_only_at(size_t idx) const noexcept {
    return originals_[idx].is_read_only();
}

// ----- write accessors -----

void Accounts::set_balance(const evmc::address& addr, const evmc::uint256be& v,
                           uint64_t tx_idx) {
    const size_t i = index_of(addr);
    mark_touched_at(i, tx_idx);
    set_balance_at(i, v);
}

void Accounts::set_nonce(const evmc::address& addr, uint64_t v,
                         uint64_t tx_idx) {
    const size_t i = index_of(addr);
    mark_touched_at(i, tx_idx);
    set_nonce_at(i, v);
}

void Accounts::set_code_hash(const evmc::address& addr, const evmc::bytes32& v,
                             uint64_t tx_idx) {
    const size_t i = index_of(addr);
    mark_touched_at(i, tx_idx);
    set_code_hash_at(i, v);
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

// ----- per-tx warm/cold tracking -----

void Accounts::mark_touched_at(size_t idx, uint64_t tx_idx) noexcept {
    auto& m = mods_[idx];
    if (tx_idx > m.last_tx_idx) {
        m.last_tx_idx = tx_idx;
    }
}

bool Accounts::is_warm_at(size_t idx, uint64_t tx_idx) const noexcept {
    return mods_[idx].last_tx_idx == tx_idx;
}

} // namespace zeg

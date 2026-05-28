#include "zeg/accounts.hpp"

#include <cstdio>

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
        ZEG_DEBUG_PRINTF("DBG missing addr 0x");
        for (int i = 0; i < 20; ++i) ZEG_DEBUG_PRINTF("%02x", addr.bytes[i]);
        ZEG_DEBUG_PRINTF("\n");
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
    set_balance_at(index_of(addr), v, tx_idx);
}

void Accounts::set_nonce(const evmc::address& addr, uint64_t v,
                         uint64_t tx_idx) {
    set_nonce_at(index_of(addr), v, tx_idx);
}

void Accounts::set_code_hash(const evmc::address& addr, const evmc::bytes32& v,
                             uint64_t tx_idx) {
    set_code_hash_at(index_of(addr), v, tx_idx);
}

void Accounts::set_balance_at(size_t idx, const evmc::uint256be& v,
                              uint64_t tx_idx) {
    auto& m = mods_[idx];
    m.balance       = v;
    m.balance_dirty = true;
    m.last_tx_idx   = tx_idx;
}

void Accounts::set_nonce_at(size_t idx, uint64_t v, uint64_t tx_idx) {
    auto& m = mods_[idx];
    m.nonce       = v;
    m.nonce_dirty = true;
    m.last_tx_idx = tx_idx;
}

void Accounts::set_code_hash_at(size_t idx, const evmc::bytes32& v,
                                uint64_t tx_idx) {
    auto& m = mods_[idx];
    m.code_hash       = v;
    m.code_hash_dirty = true;
    m.last_tx_idx     = tx_idx;
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

uint64_t Accounts::last_tx_idx_at(size_t idx) const noexcept {
    return mods_[idx].last_tx_idx;
}

void Accounts::set_warm_at(size_t idx, uint64_t tx_idx) noexcept {
    // Unconditional: unlike `mark_touched_at`, this can step
    // `last_tx_idx` backward — used by the journal's rollback path
    // to restore the pre-write value.
    mods_[idx].last_tx_idx = tx_idx;
}

void Accounts::check_read_only_unchanged() const {
    for (size_t i = 0; i < originals_.size(); ++i) {
        if (!originals_[i].is_read_only()) continue;
        if (balance_at(i)   != originals_[i].balance()) {
            ZEG_DEBUG_PRINTF("DBG read-only account mutated (balance) idx=%zu addr=0x", i);
            for (uint8_t b : originals_[i].address().bytes) ZEG_DEBUG_PRINTF("%02x", b);
            ZEG_DEBUG_PRINTF("\n");
            fatal("Accounts::check_read_only_unchanged: balance mutated");
        }
        if (nonce_at(i)     != originals_[i].nonce()) {
            ZEG_DEBUG_PRINTF("DBG read-only account mutated (nonce) idx=%zu addr=0x", i);
            for (uint8_t b : originals_[i].address().bytes) ZEG_DEBUG_PRINTF("%02x", b);
            ZEG_DEBUG_PRINTF("\n");
            fatal("Accounts::check_read_only_unchanged: nonce mutated");
        }
        if (code_hash_at(i) != originals_[i].code_hash()) {
            ZEG_DEBUG_PRINTF("DBG read-only account mutated (code_hash) idx=%zu addr=0x", i);
            for (uint8_t b : originals_[i].address().bytes) ZEG_DEBUG_PRINTF("%02x", b);
            ZEG_DEBUG_PRINTF("\n");
            fatal("Accounts::check_read_only_unchanged: code_hash mutated");
        }
    }
}

} // namespace zeg

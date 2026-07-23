#include "zeg/accounts.hpp"

#include <cstdio>

#include "zeg/fatal.hpp"
#include "zeg/hash_reserve.hpp"
#include "zeg/stream.hpp"

namespace zeg {

void Accounts::reserve(uint64_t count) {
    // Pre-size the backing buffer to exactly `count` records and fill with
    // zero (so the unused storage_root gap + any pad bytes are defined).
    // Fixed size => no realloc => stable View pointers.
    record_store_.assign(count * kRecordSize, 0);
    capacity_ = count;
    originals_.reserve(count);
    mods_.reserve(count);
    leaf_.reserve(count);
    hash_reserve_empty(index_, count);  // not .reserve(): see zeg/hash_reserve.hpp
}

size_t Accounts::append(const evmc::address&   address,
                        uint64_t               nonce,
                        const evmc::uint256be& balance,
                        const evmc::bytes32&   code_hash) {
    const size_t idx = originals_.size();
    if (idx >= capacity_) {
        fatal("Accounts::append: more rows than reserve() allowed (numberOfAccounts overflow)");
    }
    uint8_t* rec = record_store_.data() + idx * kRecordSize;
    std::memcpy(rec + View::kAddressOffset,  address.bytes,   sizeof(address.bytes));
    std::memcpy(rec + View::kBalanceOffset,  balance.bytes,   sizeof(balance.bytes));
    std::memcpy(rec + View::kNonceOffset,    &nonce,          sizeof(nonce));
    std::memcpy(rec + View::kCodeHashOffset, code_hash.bytes, sizeof(code_hash.bytes));
    originals_.push_back(View{rec});
    mods_.push_back(Mods{});
    leaf_.push_back(LeafCache{});
    index_.emplace(address, idx);
    return idx;
}

const NodeR* Accounts::build_value(size_t idx,
                                   const std::vector<uint8_t>& nib,
                                   const evmc::bytes32& addr_hash,
                                   Child storage_root_child,
                                   const evmc::bytes32& storage_root) {
    LeafCache& lc = leaf_[idx];
    lc.addr_hash    = addr_hash;
    lc.storage_root = storage_root_child;
    // Build from the ORIGINAL (block-start) fields.
    if (is_empty_account(nonce_orig_at(idx), balance_orig_at(idx), code_hash_orig_at(idx))) {
        lc.cached.emplace<EmptyR>();
    } else {
        lc.cached.emplace<AccountLeafR>(nib, idx, storage_root);
    }
    return &lc.cached;
}

const NodeR* Accounts::update_value(size_t idx,
                                    const std::vector<uint8_t>& nib,
                                    const evmc::bytes32& storage_root) {
    LeafCache& lc = leaf_[idx];
    // Always rebuild from the CURRENT fields + storage root at path `nib`.
    // This is cheap (no keccak — packing happens at the parent branch) and
    // keeps the leaf path correct even when a new-root insert moved this
    // leaf deeper via a split. The keccak-saving read-only reuse happens at
    // the BRANCH level (a read-only branch reuses its cached hash).
    if (is_empty_account(nonce_at(idx), balance_at(idx), code_hash_at(idx))) {
        lc.cached.emplace<EmptyR>();
    } else {
        lc.cached.emplace<AccountLeafR>(nib, idx, storage_root);
    }
    return &lc.cached;
}

void Accounts::set_addr_hash(size_t idx, const evmc::bytes32& addr_hash) {
    leaf_[idx].addr_hash = addr_hash;
}

void Accounts::set_storage_root_child(size_t idx, Child storage_root) {
    leaf_[idx].storage_root = storage_root;
}

size_t Accounts::index_of(const evmc::address& addr) const {
    const auto it = index_.find(addr);
    if (it == index_.end()) {
        std::fprintf(stderr, "DBG missing addr 0x");
        for (int i = 0; i < 20; ++i) std::fprintf(stderr, "%02x", addr.bytes[i]);
        std::fprintf(stderr, "\n");
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

void Accounts::record_phantom_account(const evmc::bytes32& addr_hash,
                                      uint64_t nonce,
                                      const evmc::uint256be& balance,
                                      const evmc::bytes32& code_hash,
                                      const evmc::bytes32& storage_root) {
    phantom_accounts_.emplace(addr_hash,
                              PhantomAccount{nonce, balance, code_hash, storage_root});
}

const Accounts::PhantomAccount* Accounts::phantom_account(
    const evmc::bytes32& addr_hash) const {
    const auto it = phantom_accounts_.find(addr_hash);
    return it == phantom_accounts_.end() ? nullptr : &it->second;
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

const evmc::uint256be& Accounts::balance_orig_at(size_t idx) const noexcept {
    return originals_[idx].balance();
}

uint64_t Accounts::nonce_orig_at(size_t idx) const noexcept {
    return originals_[idx].nonce();
}

const evmc::bytes32& Accounts::code_hash_orig_at(size_t idx) const noexcept {
    return originals_[idx].code_hash();
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

} // namespace zeg

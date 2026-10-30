#include "zeg/zisk_state_db.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <optional>
#include <vector>

#include <intx/intx.hpp>    // 256-bit add for selfdestruct balance transfer
#include <test/state/precompiles.hpp>  // evmone::state::call_precompile
#include <evmone/constants.hpp>  // COST_PER_STATE_BYTE, NEW_ACCOUNT_STATE_GAS (EIP-8037)
#include <evmone/state_gas.hpp>  // evmone::StateGas (EIP-8037)

// The owned VM, behind the evmc2 interface. The backend is selected at build
// time: EVM_BACKEND=zevm defines USE_ZEVM and links the hand-written EVM;
// otherwise the evmone-baseline adapter.
#if defined(USE_ZEVM)
#include "zevm/zevm.hpp"     // evmc2_create_zevm
#else
#include "evmc2_evmone.hpp"  // evmc2_create_evmone
#endif

#include "zeg/bloom.hpp"
#include "zeg/config.hpp"
#include "zeg/create_address.hpp"
#include "zeg/eip6110_deposit.hpp"
#include "zeg/fake_exponential.hpp"
#include "zeg/fatal.hpp"
#include "zeg/intrinsic_gas.hpp"
#include "zeg/keccak.hpp"
#include "zeg/mpt.hpp"
#include "zeg/receipt.hpp"
#include "zeg/rlp.hpp"
#include "zeg/sha256.hpp"
#include "zeg/system_addresses.hpp"
#include "zeg/heap_stats.hpp"
#include "zeg/tx_arena.hpp"
#include "zeg/zisk_crypto.hpp"  // verify_signature_and_get_signer (EIP-7702)

namespace zeg {

namespace {

// Code deposit for a successful CREATE whose code passed the size and
// 0xef checks. Before Amsterdam: 200 gas per byte (EIP-2). Amsterdam
// (EIP-8037): 6 gas per word for hashing, plus COST_PER_STATE_BYTE per
// byte of state gas, taken from the initcode's leftover reservoir first
// (evmone test/state/host.cpp). Returns false when the frame can't pay;
// the CREATE then fails with all its gas consumed.
bool charge_code_deposit(evmc::Result& result, bool amsterdam) noexcept {
    const auto size = static_cast<int64_t>(result.output_size);
    if (!amsterdam) {
        if (result.gas_left < size * 200) return false;
        result.gas_left -= size * 200;
        return true;
    }
    int64_t gas_left = result.gas_left - 6 * ((size + 31) / 32);
    evmone::StateGas state_gas{result.state_gas};
    if (gas_left < 0 ||
        !state_gas.charge(gas_left, size * evmone::COST_PER_STATE_BYTE)) {
        return false;
    }
    result.gas_left  = gas_left;
    result.state_gas = state_gas;
    return true;
}

// keccak256 of the empty byte string. An account whose code_hash equals
// this is considered to have no code (per Yellow Paper §4.1).
constexpr evmc::bytes32 EMPTY_CODE_HASH{{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
}};

// EVMC SSTORE status code per the EVMC spec (full 9-state table). The
// inputs are: `original` = slot value at the start of the current tx
// (EIP-2200), `current` = value right before this write, `new_value`
// = value being written.
evmc_storage_status compute_storage_status(const evmc::bytes32& original,
                                           const evmc::bytes32& current,
                                           const evmc::bytes32& new_value) {
    constexpr evmc::bytes32 zero{};

    if (new_value == current) {
        return EVMC_STORAGE_ASSIGNED;
    }
    if (original == current) {
        // First write in this tx.
        if (original  == zero) return EVMC_STORAGE_ADDED;
        if (new_value == zero) return EVMC_STORAGE_DELETED;
        return EVMC_STORAGE_MODIFIED;
    }
    // Already dirtied in this tx (current != original).
    if (original != zero && current == zero) {
        // X -> 0 -> ?
        return (new_value == original) ? EVMC_STORAGE_DELETED_RESTORED
                                       : EVMC_STORAGE_DELETED_ADDED;
    }
    if (original != zero && new_value == zero) {
        return EVMC_STORAGE_MODIFIED_DELETED;
    }
    if (original == zero && new_value == zero) {
        return EVMC_STORAGE_ADDED_DELETED;  // 0 -> X -> 0
    }
    if (original == new_value) {
        return EVMC_STORAGE_MODIFIED_RESTORED;
    }
    return EVMC_STORAGE_ASSIGNED;  // X -> Y -> Z fallback
}

} // namespace

// ===== Constructor =====

ZiskStateDB::ZiskStateDB(Accounts&             accounts,
                         const ConsensusInfo&  consensus,
                         Contracts&            contracts,
                         const PreviousBlocks& previous_blocks,
                         Storages&             storages,
                         const zeg::HashSeed&  table_seed)
    : accounts_(accounts),
      consensus_(consensus),
      contracts_(contracts),
      previous_blocks_(previous_blocks),
      storages_(storages),
      vm2_(
#if defined(USE_ZEVM)
          evmc2_create_zevm()
#else
          evmc2_create_evmone()
#endif
          ),
      transient_(table_seed),
      warm_keys_(table_seed) {
#ifndef ZEG_ANALYSIS_CACHE_SLOTS
#define ZEG_ANALYSIS_CACHE_SLOTS 1152u
#endif
    // Fixed, reusable cache for per-contract JUMPDEST analyses (bounds the heap
    // regardless of how many distinct contracts a block executes). Sized in
    // slots above the max simultaneously-pinned set (<= call depth + 1 = 1025),
    // so eviction never has to fail a valid block; the bytes follow from the
    // backend's slot size.
    static_assert(ZEG_ANALYSIS_CACHE_SLOTS > 1025u,
                  "the analysis cache must hold every live frame's analysis");
    cache_ = new AnalysisCache(vm2_,
                               std::size_t{ZEG_ANALYSIS_CACHE_SLOTS} * vm2_->analysis_slot_bytes,
                               vm2_->analysis_slot_bytes, kMaxCodeSizeAmsterdam);
}

ZiskStateDB::~ZiskStateDB() {
    // Drop the analysis cache (clears the Contracts' cached handles and frees
    // the arena) before destroying the VM. Slot-backed analyses are owned by
    // the cache, so there is no per-handle VM release.
    delete cache_;
    vm2_->base.destroy(&vm2_->base);
}

size_t ZiskStateDB::max_code_size() const noexcept {
    return is_amsterdam_or_later() ? kMaxCodeSizeAmsterdam : kMaxCodeSize;
}

size_t ZiskStateDB::max_initcode_size() const noexcept {
    return is_amsterdam_or_later() ? kMaxInitCodeSizeAmsterdam : kMaxInitCodeSize;
}

// ===== evmc::Host overrides =====
//
// In header declaration order. Most are direct pass-throughs to the
// corresponding Accounts/Storages accessor; the execution-driving ones
// (call, emit_log, access_account, access_storage) do real work.

bool ZiskStateDB::account_exists(const evmc::address& addr) const noexcept {
    bal_commit_pending();
    // "Exists" = non-empty (nonzero balance OR nonce OR non-empty code).
    // An account that doesn't exist is still a row (an empty leaf).
    const size_t idx = account_row(addr);
    // EIP-7928: the VM asks this for a CALL / SELFDESTRUCT target's
    // new-account charge, after its cold-access charge: a load.
    const_cast<Accounts&>(accounts_).bal_access_at(idx);
    if (accounts_.nonce_at(idx) != 0) {
        return true;
    }
    if (accounts_.code_hash_at(idx) != EMPTY_CODE_HASH) {
        return true;
    }
    const auto bal = accounts_.balance_at(idx);
    for (uint8_t b : bal.bytes) {
        if (b != 0) {
            return true;
        }
    }
    return false;
}

evmc::bytes32 ZiskStateDB::get_storage(const evmc::address& addr,
                                       const evmc::bytes32& key) const noexcept {
    bal_commit_pending();
    const size_t idx = storage_row(addr, key);
    if (bal_) const_cast<ZiskStateDB*>(this)->bal_slot(idx);
    // What `storages_.value(addr, key, tx)` does, minus its second probe of
    // the same key: touch the slot for tx_counter_ (snapshots tx_original on
    // first access, marks warm), then read. The const_cast is safe: mods_ is
    // logically mutable scratch — evmc::Host::get_storage is const-by-
    // interface but the per-tx tracking has to happen here.
    auto& s = const_cast<Storages&>(storages_);
    s.mark_touched_at(idx, tx_counter_);
    return s.value_at(idx);
}

evmc_storage_status ZiskStateDB::set_storage(const evmc::address& addr,
                                             const evmc::bytes32& key,
                                             const evmc::bytes32& value) noexcept {
    bal_commit_pending();
    const size_t idx = storage_row(addr, key);

    // No explicit mark_touched_at here: on Berlin+ revisions evmone
    // always calls access_storage(addr, key) before set_storage, and
    // our access_storage already does the snapshot. So by the time
    // we read tx_original_at below the per-tx-original is in place.
    const auto& original = storages_.tx_original_at(idx);
    const auto  current  = storages_.value_at(idx);
    if (bal_) bal_->open_slot(bal_slot(idx), current);

    journal_.log_storage(idx, current, storages_.last_tx_idx_at(idx));
    storages_.set_value_at(idx, value, tx_counter_);

    return compute_storage_status(original, current, value);
}

evmc::bytes32 ZiskStateDB::get_transient_storage(const evmc::address& addr,
                                                 const evmc::bytes32& key) const noexcept {
    bal_commit_pending();
    return transient_.get(addr, key);
}

void ZiskStateDB::set_transient_storage(const evmc::address& addr,
                                        const evmc::bytes32& key,
                                        const evmc::bytes32& value) noexcept {
    bal_commit_pending();
    // Snapshot the slot's pre-write state and journal it BEFORE the
    // mutation so an enclosing revert can restore it. EIP-1153 only
    // requires per-frame reset (handled at tx/system-call boundaries)
    // + per-revert rollback; no warm/cold or "original" semantics.
    const auto prev = transient_.set(addr, key, value);
    journal_.log_transient(addr, key, prev.was_present, prev.value);
}

evmc::uint256be ZiskStateDB::get_balance(const evmc::address& addr) const noexcept {
    bal_commit_pending();
    // const_cast: the per-tx warm-touch mutates accounts_.mods_,
    // which is logically scratch state. Same pattern as get_storage.
    return const_cast<Accounts&>(accounts_).balance(addr, tx_counter_);
}

uint64_t ZiskStateDB::get_nonce(const evmc::address& addr) const noexcept {
    // The VM asks for the creator's nonce to derive a CREATE address.
    return const_cast<Accounts&>(accounts_).nonce(addr, tx_counter_);
}

size_t ZiskStateDB::get_code_size(const evmc::address& addr) const noexcept {
    bal_commit_pending();
    const auto hash = const_cast<Accounts&>(accounts_).code_hash(addr, tx_counter_);
    if (hash == EMPTY_CODE_HASH) {
        return 0;
    }
    return static_cast<size_t>(contracts_.by_hash(hash).code_size);
}

evmc::bytes32 ZiskStateDB::get_code_hash(const evmc::address& addr) const noexcept {
    bal_commit_pending();
    // EIP-1052: EXTCODEHASH of a non-existent (empty) account is 0,
    // NOT keccak256("") (= EMPTY_CODE_HASH). "Empty" per EIP-161
    // means nonce == 0 AND balance == 0 AND code_hash == EMPTY.
    // Distinct from "account exists but has no deployed code", which
    // correctly returns EMPTY_CODE_HASH.
    //
    // Block 25200801 tx 79 hit this: an OpenSea ERC-1155 storefront
    // does `EXTCODEHASH(unused-addr) == 0` as a "is this an EOA?"
    // check; returning EMPTY_CODE_HASH instead made the check fail
    // and the tx took a different branch.
    if (!account_exists(addr)) {
        return {};
    }
    return const_cast<Accounts&>(accounts_).code_hash(addr, tx_counter_);
}

size_t ZiskStateDB::copy_code(const evmc::address& addr,
                              size_t offset,
                              uint8_t* buffer,
                              size_t buffer_size) const noexcept {
    bal_commit_pending();
    const auto hash = const_cast<Accounts&>(accounts_).code_hash(addr, tx_counter_);
    if (hash == EMPTY_CODE_HASH) {
        return 0;
    }
    const auto& c = contracts_.by_hash(hash);
    if (offset >= c.code_size) {
        return 0;
    }
    const size_t remaining = static_cast<size_t>(c.code_size) - offset;
    const size_t n         = remaining < buffer_size ? remaining : buffer_size;
    std::memcpy(buffer, c.code + offset, n);
    return n;
}

bool ZiskStateDB::selfdestruct(const evmc::address& addr,
                               const evmc::address& beneficiary) noexcept {
    bal_commit_pending();
    // Pre-Cancun: SELFDESTRUCT always fully destroys the account —
    // balance moves to the beneficiary, then nonce / code_hash / every
    // storage slot are cleared and the leaf disappears from the state
    // trie (`return true`), unconditionally, regardless of whether the
    // contract was created this tx.
    //
    // EIP-6780 (Cancun) narrows this: full destruction only happens if
    // the contract was CREATEd earlier in THIS transaction. Otherwise
    // only the balance is transferred and the account is preserved
    // (`return false`).
    //
    // All field clears go through the journal so a revert of the
    // surrounding frame restores the contract intact.
    const size_t src_idx = account_row(addr);
    const bool same_tx_created = created_this_tx_idx_.count(src_idx) != 0;
    const bool should_destroy  = is_cancun_or_later() ? same_tx_created : true;

    if (addr == beneficiary) {
        if (should_destroy) {
            // A same-tx-created contract that self-destructs to itself
            // still burns its balance immediately (it never reaches the
            // beneficiary since there isn't a distinct one) — matches
            // revm's journal `selfdestruct()`: the source's balance is
            // unconditionally zeroed whenever `should_destroy` is true,
            // regardless of whether target == address; only the truly
            // no-op case (should_destroy == false, self-beneficiary) skips
            // the balance write entirely. EIP-8246 (Amsterdam): no burn —
            // the balance stays and survives the end-of-tx clear.
            if (!is_amsterdam_or_later()) {
                journal_.log_balance(src_idx, accounts_.balance_at(src_idx),
                                     accounts_.last_tx_idx_at(src_idx));
                accounts_.set_balance_at(src_idx, evmc::uint256be{}, tx_counter_);
            }
            // Defer destruction to end-of-tx per Yellow Paper —
            // see comment on pending_destruct_ in the header.
            const auto [_, inserted] = pending_destruct_.insert(src_idx);
            journal_.log_pending_destruct(src_idx, /*was_already_present=*/!inserted);
            // Only the FIRST selfdestruct of a given address this tx is
            // "newly destroyed" — evmone grants the (pre-London) 24000
            // refund only when this returns true, and a repeat
            // selfdestruct on an address already pending destruction
            // must not grant it again (matches revm's
            // `!previously_destroyed` gate).
            return inserted;
        }
        // should_destroy == false, self-beneficiary: true no-op, balance
        // stays exactly as-is (matches revm's `else { None }` branch).
        return false;
    }

    // Log + transfer balance.
    const size_t dst_idx = account_row(beneficiary);
    journal_.log_balance(src_idx, accounts_.balance_at(src_idx),
                         accounts_.last_tx_idx_at(src_idx));
    journal_.log_balance(dst_idx, accounts_.balance_at(dst_idx),
                         accounts_.last_tx_idx_at(dst_idx));

    const auto src_u = intx::be::load<intx::uint256>(accounts_.balance_at(src_idx));
    const auto dst_u = intx::be::load<intx::uint256>(accounts_.balance_at(dst_idx));
    accounts_.set_balance_at(dst_idx,
                             intx::be::store<evmc::uint256be>(dst_u + src_u),
                             tx_counter_);
    accounts_.set_balance_at(src_idx, evmc::uint256be{}, tx_counter_);
    emit_transfer_log(addr, beneficiary, intx::be::store<evmc::uint256be>(src_u));

    if (should_destroy) {
        // Defer destruction to end-of-tx per Yellow Paper.
        const auto [_, inserted] = pending_destruct_.insert(src_idx);
        journal_.log_pending_destruct(src_idx, /*was_already_present=*/!inserted);
        // Only the FIRST selfdestruct of a given address this tx is
        // "newly destroyed" — see the same-beneficiary branch above.
        return inserted;
    }
    return false;
}

void ZiskStateDB::apply_pending_destructs() noexcept {
    // Called once per tx after the EVM completes. Each pending entry
    // gets its full clear (nonce + code_hash + storage). No journaling
    // needed — the tx has committed and no revert can roll these back.
    for (size_t idx : pending_destruct_) {
        clear_account_for_selfdestruct(idx);
    }
    pending_destruct_.clear();
}

void ZiskStateDB::clear_account_for_selfdestruct(size_t src_idx) noexcept {
    // EIP-6780 full-destroy helper, run once per tx (from
    // apply_pending_destructs) after the whole top-level frame has
    // finished — destruction is deferred to end-of-tx, so the account
    // keeps functioning normally (including receiving further value) in
    // between its own SELFDESTRUCT call and this point. The original
    // SELFDESTRUCT call already swept whatever balance existed *at that
    // moment* to the beneficiary (or skipped it for the self-as-
    // beneficiary edge case) — but any value the account received
    // *afterward* (e.g. a plain CALL with value, or another contract's
    // SELFDESTRUCT naming it beneficiary) never went anywhere and is
    // still sitting on the account here. A destroyed account can't
    // survive in the new trie with a nonzero balance (EIP-161 emptiness
    // requires balance == 0 too, not just nonce/code), so zero it now —
    // per Yellow Paper / real-client behavior, that late-arriving value
    // is simply burned, not returned or re-swept.
    //
    // EIP-8246 (Amsterdam): no burn. The balance is kept and the rest of
    // the account is cleared below, so a non-zero balance leaves a
    // balance-only account (nonce 0, no code, empty storage); a zero one
    // is empty and drops out of the trie as before.
    if (!is_amsterdam_or_later()) {
        journal_.log_balance(src_idx, accounts_.balance_at(src_idx),
                             accounts_.last_tx_idx_at(src_idx));
        accounts_.set_balance_at(src_idx, evmc::uint256be{}, tx_counter_);
    }

    // Account fields.
    journal_.log_nonce(src_idx, accounts_.nonce_at(src_idx),
                       accounts_.last_tx_idx_at(src_idx));
    accounts_.set_nonce_at(src_idx, 0, tx_counter_);

    journal_.log_code_hash(src_idx, accounts_.code_hash_at(src_idx),
                           accounts_.last_tx_idx_at(src_idx));
    accounts_.set_code_hash_at(src_idx, EMPTY_CODE_HASH, tx_counter_);

    // Storage: zero every (addr, slot) entry in the witness for this
    // address. `Storages::slots_of` returns this account's slot indices
    // in O(1) via an address->indices hashmap built at construction —
    // independent of the table sort order (the table is now keccak-sorted
    // for the StateRoot leaf counter, not raw-address-sorted).
    const evmc::address& addr = accounts_.address_at(src_idx);
    for (size_t i : storages_.slots_of(addr)) {
        const auto cur = storages_.value_at(i);
        if (cur == evmc::bytes32{}) continue;
        // EIP-7928: a slot with a BAL record gets its period opened before
        // the wipe. (One without was never loaded, so it still holds its
        // block-start value, which a same-tx-created account can't have.)
        if (bal_ && storages_.bal_id_at(i) != BlockAccessList::kNone) {
            bal_->open_slot(bal_->slot(storages_.bal_id_at(i)), cur);
        }
        journal_.log_storage(i, cur, storages_.last_tx_idx_at(i));
        storages_.set_value_at(i, evmc::bytes32{}, tx_counter_);
    }

    // The block-start storage trie (incl. preimage-less slots we couldn't
    // zero above) is gone too — a later CREATE here must not collide on it.
    storage_wiped_idx_.insert(src_idx);
}

evmc::Result ZiskStateDB::call(const evmc_message& msg) noexcept {
    // The EVM stops CALL/CREATE at depth 1024 (patch 15 for evmone, zevm's own
    // check), so a deeper message is a broken invariant. evmone keeps only 1025
    // ExecutionStates; going deeper would reallocate them under live frames.
    if (msg.depth > 1024) fatal("call: depth > 1024");
    bal_commit_pending();
    // Precompile dispatch. Mirror the test/state host check: only a
    // straight CALL (not a DELEGATECALL into the precompile address)
    // hits the precompile dispatcher — DELEGATECALL into a precompile
    // address runs the caller's code with the precompile's "code"
    // (which is empty), per EVM semantics.
    if ((msg.flags & EVMC_DELEGATED) == 0 &&
        evmone::state::is_precompile(active_revision(), msg.code_address)) {
        if (bal_) bal_load(msg.code_address);  // EIP-7928: the call loads it
        // A plain CALL with value to a precompile still transfers the value
        // to the precompile address (then the precompile runs). STATICCALL
        // (value forced to 0 by EIP-214) and CALLCODE/DELEGATECALL (no
        // transfer) are naturally excluded by the kind/value guards. Snapshot
        // so a failing precompile (e.g. OOG) rolls the transfer back. Fixture
        // test_precompile_will_return_success_with_tx_value (P256VERIFY, 0x100)
        // exercises this — the precompile address must end credited.
        if (msg.kind == EVMC_CALL &&
            intx::be::load<intx::uint256>(msg.value) != 0) {
            const auto pcp = checkpoint();
            transfer_value(msg.sender, msg.recipient, msg.value);
            auto result = call_precompile_dispatch(msg);
            if (result.status_code != EVMC_SUCCESS) {
                rollback(pcp);
            }
            return result;
        }
        return call_precompile_dispatch(msg);
    }

    // Snapshot state up front. Any non-success status from the nested
    // frame rolls back every write made under it.
    const auto cp = checkpoint();

    std::span<const uint8_t> code;
    evmc::bytes32            code_hash{};

    switch (msg.kind) {
        case EVMC_CALL: {
            // CALL transfers `value` from sender to recipient.
            // STATICCALL is just an EVMC_CALL with msg.flags &
            // EVMC_STATIC and value forced to 0 by EIP-214, so the
            // `v_u != 0` guard naturally skips the transfer for it.
            // DELEGATECALL/CALLCODE never transfer (handled below).
            const auto v_u = intx::be::load<intx::uint256>(msg.value);
            if (v_u != 0) {
                transfer_value(msg.sender, msg.recipient, msg.value);
            }
            code = this->code_and_hash(msg.code_address, code_hash);
            break;
        }
        case EVMC_CALLCODE:
        case EVMC_DELEGATECALL:
            // No value transfer (DELEGATECALL's `value` is apparent
            // only; CALLCODE keeps the value in the caller's storage).
            code = this->code_and_hash(msg.code_address, code_hash);
            break;

        case EVMC_CREATE:
        case EVMC_CREATE2:
            return call_create(msg, cp);
    }

    auto result = evmc::Result{run_frame(&msg, code.data(), code.size(),
        analysis_for(code_hash))};
    if (result.status_code != EVMC_SUCCESS) {
        rollback(cp);
    }
    return result;
}

evmc::Result ZiskStateDB::call_precompile_dispatch(const evmc_message& msg) noexcept {
    // ECRECOVER lives at address 0x00..01. Route it to the accelerated recover;
    // all other precompiles keep going through evmone.
    const auto& a = msg.code_address;
    bool is_ecrecover = (a.bytes[19] == 0x01);
    for (int i = 0; i < 19 && is_ecrecover; ++i)
        if (a.bytes[i] != 0) is_ecrecover = false;
    if (is_ecrecover)
        return ecrecover_precompile(msg);
    return evmone::state::call_precompile(active_revision(), msg);
}

evmc::Result ZiskStateDB::ecrecover_precompile(const evmc_message& msg) noexcept {
    // Flat 3000 gas; insufficient gas fails the call outright (no output).
    constexpr int64_t kEcrecoverGas = 3000;
    if (msg.gas < kEcrecoverGas) {
        return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0,
                            {.left = msg.state_gas}};
    }
    const int64_t gas_left = msg.gas - kEcrecoverGas;

    // Input is zero-padded to 128 bytes: hash[32] | v[32] | r[32] | s[32].
    uint8_t in[128] = {};
    const size_t n = msg.input_size < 128 ? msg.input_size : 128;
    if (msg.input_data != nullptr && n > 0)
        std::memcpy(in, msg.input_data, n);

    // v is a 256-bit BE integer that must equal 27 or 28; recid = v - 27.
    bool v_ok = (in[63] == 27 || in[63] == 28);
    for (size_t i = 32; i < 63 && v_ok; ++i)
        if (in[i] != 0) v_ok = false;
    if (!v_ok)
        return evmc::Result{EVMC_SUCCESS, gas_left, 0, nullptr, 0,
                            {.left = msg.state_gas}};  // empty output
    const unsigned recid = static_cast<unsigned>(in[63] - 27);

    evmc::bytes32   hash;  std::memcpy(hash.bytes, in,      32);
    evmc::uint256be r;     std::memcpy(r.bytes,    in + 64, 32);
    evmc::uint256be s;     std::memcpy(s.bytes,    in + 96, 32);

    evmc::address signer{};
    if (!ecrecover_address(hash, r, s, recid, signer))
        return evmc::Result{EVMC_SUCCESS, gas_left, 0, nullptr, 0,
                            {.left = msg.state_gas}};  // not recoverable

    // Output: 20-byte address, left-padded to 32 bytes. evmc::Result copies it.
    uint8_t out[32] = {};
    std::memcpy(out + 12, signer.bytes, 20);
    return evmc::Result{EVMC_SUCCESS, gas_left, 0, out, sizeof(out),
                        {.left = msg.state_gas}};
}

evmc_tx_context ZiskStateDB::get_tx_context() const noexcept {
    bal_commit_pending();
    return tx_context_;
}

evmc::bytes32 ZiskStateDB::get_block_hash(int64_t block_number) const noexcept {
    bal_commit_pending();
    const int64_t current = static_cast<int64_t>(consensus_.number());
    const int64_t diff    = current - block_number;
    // EVM BLOCKHASH semantics: zero outside the opcode's [1, 256] depth window.
    if (diff < 1 || diff > 256) {
        return {};
    }
    const uint64_t target = static_cast<uint64_t>(block_number);
#if !defined(ZEG_ZISK)
    // DEBUG (host): report each BLOCKHASH depth used (see Contracts::index_of).
    static const bool dump_used = std::getenv("ZEG_DUMP_USED") != nullptr;
    if (dump_used) std::fprintf(stderr, "USED blockhash %llu\n", static_cast<unsigned long long>(target));
#endif

    // Serve BLOCKHASH from the input's block chain. PreviousBlocks has already
    // verified that the WHOLE list is a contiguous parent_hash-linked chain
    // anchored at index 0 (the parent, whose hash is pinned to the committed
    // block's parent_hash — see run.cpp), so every record is provably the real
    // ancestor and a forged or gapped list is rejected at construction. The
    // witness carries every block from the parent down to the deepest BLOCKHASH
    // target, so an in-window number that is missing means an incomplete
    // witness — halt rather than return an unproven hash.
    //
    // NB: EIP-2935's start-of-block system call still runs in pre_execute_block
    // (it updates the history-storage contract's state); it is simply not used
    // as the BLOCKHASH source. consensus.parent_hash() is the parent's
    // STATE_ROOT in this guest's binary format, NOT the parent's block hash.
    if (const evmc::bytes32* h = previous_blocks_.hash_of_number(target)) {
        return *h;
    }
    zeg::fatal("get_block_hash: requested ancestor not in the verified block chain");
    return {};
}

void ZiskStateDB::emit_log(const evmc::address& addr,
                           const uint8_t* data,
                           size_t data_size,
                           const evmc::bytes32 topics[],
                           size_t topics_count) noexcept {
    bal_commit_pending();
    // The current tx's receipt was pushed onto tx_receipts_ at the
    // start of the iteration in process_transactions; we just append
    // the log here. Owned copies so the EVM is free to release its
    // buffers after this returns.
    if (in_system_call_) {
        return;
    }
    LogEntry entry;
    entry.address = addr;
    entry.topics.assign(topics, topics + topics_count);
    entry.data.assign  (data,   data   + data_size);
    tx_receipts_.back().logs.push_back(std::move(entry));
}

evmc_access_status ZiskStateDB::access_account(const evmc::address& addr) noexcept {
    bal_commit_pending();
    // EIP-2929 account warm/cold: warm iff the account was already
    // touched in this tx (last_tx_idx == tx_counter_). Either way,
    // touch it now so the next access sees it warm. Same pattern as
    // access_storage.
    //
    // EIP-2929 precompile carve-out: ALL precompiles are inherently
    // warm at every access, regardless of whether the host's Accounts
    // table includes them. Short-circuit here so callers don't need
    // to inject precompile entries into the prestate.
    if (evmone::state::is_precompile(active_revision(), addr)) {
        if (bal_) bal_pending_ = pending_row(addr);  // EIP-7928, see below
        return EVMC_ACCESS_WARM;
    }
    // Warming is not a load: an address without a row (whose gas charge may
    // then fail) only gets its warmth tracked. A load that follows needs the
    // row.
    if (!accounts_.contains(addr)) {
        const uint64_t last = warm_keys_.account(addr);
        if (last != tx_counter_) {
            journal_.log_warm_key_account(addr, last);
            warm_keys_.set_account(addr, tx_counter_);
        }
        if (bal_) bal_pending_ = kMissingRow;
        return last == tx_counter_ ? EVMC_ACCESS_WARM : EVMC_ACCESS_COLD;
    }
    const size_t idx      = accounts_.index_of(addr);
    const bool   was_warm = accounts_.is_warm_at(idx, tx_counter_);
    if (!was_warm) {
        // Journal the cold→warm transition so a reverted EVM frame
        // restores cold-ness (EIP-2929 / EIP-2200 gas accounting).
        journal_.log_account_warm(idx, accounts_.last_tx_idx_at(idx));
    }
    accounts_.mark_touched_at(idx, tx_counter_);
    // EIP-7928: the VM charges the access cost after this returns; the
    // account counts as loaded only if that charge succeeds, which shows as
    // a further host callback in the same frame or the frame ending
    // normally (run_frame drops it on an exceptional halt). Matches revm
    // skipping a cold load it can't pay for.
    if (bal_) bal_pending_ = idx;
    return was_warm ? EVMC_ACCESS_WARM : EVMC_ACCESS_COLD;
}

evmc_access_status ZiskStateDB::access_storage(const evmc::address& addr,
                                               const evmc::bytes32& key) noexcept {
    bal_commit_pending();
    // Warming is not a load: a slot without a row only gets its warmth
    // tracked; the SLOAD / SSTORE that follows needs the row.
    const size_t idx = storages_.find(addr, key);
    if (idx == Storages::npos) {
        const uint64_t last = warm_keys_.slot(addr, key);
        if (last != tx_counter_) {
            journal_.log_warm_key_slot(addr, key, last);
            warm_keys_.set_slot(addr, key, tx_counter_);
        }
        return last == tx_counter_ ? EVMC_ACCESS_WARM : EVMC_ACCESS_COLD;
    }

    // EIP-2929 warm/cold: a slot is warm iff it was already touched in
    // this tx (last_tx_idx == tx_counter_). Either way, touch it now
    // so the next access sees it warm.
    const bool was_warm = storages_.is_warm_at(idx, tx_counter_);
    if (!was_warm) {
        // Journal the cold→warm transition so a reverted EVM frame
        // restores cold-ness (EIP-2929 / EIP-2200 gas accounting).
        journal_.log_storage_warm(idx, storages_.last_tx_idx_at(idx));
    }
    storages_.mark_touched_at(idx, tx_counter_);
    return was_warm ? EVMC_ACCESS_WARM : EVMC_ACCESS_COLD;
}

// ===== Public methods =====

std::span<const uint8_t> ZiskStateDB::code(const evmc::address& addr) const noexcept {
    evmc::bytes32 ignored;
    return code_and_hash(addr, ignored);
}

std::span<const uint8_t> ZiskStateDB::code_and_hash(
        const evmc::address& addr, evmc::bytes32& out_hash) const noexcept {
    out_hash = EMPTY_CODE_HASH;
    const auto hash = const_cast<Accounts&>(accounts_).code_hash(addr, tx_counter_);
    if (hash == EMPTY_CODE_HASH) {
        return {};
    }
    out_hash = hash;
    const auto& c = contracts_.by_hash(hash);
    return std::span<const uint8_t>{c.code, static_cast<size_t>(c.code_size)};
}

evmc2_pre_execution* ZiskStateDB::analysis_for(const evmc::bytes32& code_hash) noexcept {
    if (code_hash == EMPTY_CODE_HASH) {
        return nullptr;  // no code → nothing to pre-analyze
    }
    const auto& c = contracts_.by_hash(code_hash);
    // Acquire (preparing on a cache miss) and PIN the analysis for the frame
    // about to run; run_frame() releases the pin when that frame returns. The
    // cache keeps it in a fixed arena slot and may evict it later (when no frame
    // pins it) to bound heap use. c.analysis is the cached slot handle, nulled
    // by the cache on eviction.
    return cache_->acquire(&c.analysis, c.code, static_cast<size_t>(c.code_size));
}

void ZiskStateDB::set_tx_context(const evmc_tx_context& ctx) noexcept {
    tx_context_ = ctx;
}

ZiskStateDB::Checkpoint ZiskStateDB::checkpoint() noexcept {
    // Snapshot the current tx's logs size alongside the journal cp so
    // a reverted frame drops its emissions too.
    return Checkpoint{
        journal_.checkpoint(),
        tx_receipts_.empty() ? size_t{0} : tx_receipts_.back().logs.size(),
    };
}

void ZiskStateDB::rollback(Checkpoint cp) noexcept {
    journal_.rollback(cp.journal_cp, accounts_, storages_, warm_keys_, transient_, pending_destruct_);
    if (!tx_receipts_.empty()) {
        tx_receipts_.back().logs.resize(cp.log_count);
    }
}

void ZiskStateDB::execute_block(const Transactions& transactions) noexcept {
    pre_execute_block ();
    process_transactions(transactions);
    heap_mark("txs");
    post_execute_block();

    // EIP-7928: the BAL.
    if (bal_) bal_hash_ = build_block_access_list_hash();
    heap_mark("bal");

    // Receipts trie root: built from the finalized tx_receipts_, one
    // leaf per tx keyed by RLP(tx_index).
    {
        MerklePatriciaTrie trie;
        for (size_t i = 0; i < tx_receipts_.size(); ++i) {
            trie.insert(rlp::encode_u64(i), encode_receipt(tx_receipts_[i]));
        }
        receipts_root_ = trie.root_hash();
    }
    heap_mark("receipts");

    // Withdrawals trie root (EIP-4895): one leaf per withdrawal, keyed
    // by RLP(index_in_block), value = rlp_list(index, validator_index,
    // address, amount_gwei). Empty list → empty-trie root.
    {
        MerklePatriciaTrie trie;
        for (size_t i = 0; i < consensus_.withdrawals_count(); ++i) {
            const auto& w           = consensus_.withdrawal(i);
            const auto  index_rlp           = rlp::encode_u64(w.index());
            const auto  validator_index_rlp = rlp::encode_u64(w.validator_index());
            const auto  address_rlp         = rlp::encode(rlp::BytesView{w.address().bytes,
                                                                          sizeof(w.address().bytes)});
            const auto  amount_rlp          = rlp::encode_u64(w.amount_gwei());
            auto record = rlp::encode_list({index_rlp,
                                            validator_index_rlp,
                                            address_rlp,
                                            amount_rlp});
            withdrawals_rlp_list_payload_size_ += record.size();
            trie.insert(rlp::encode_u64(i), std::move(record));
        }
        withdrawals_root_ = trie.root_hash();
    }

    // EIP-7685 requests_hash: sha256(sha256(req[0]) || sha256(req[1])
    // || ...) over the type-prefixed request blobs in requests_.
    // Empty list collapses to sha256("") per the EIP.
    {
        std::vector<uint8_t> concatenated;
        concatenated.reserve(requests_.size() * 32);
        for (const auto& req : requests_) {
            const auto inner = sha256_bytes32(req.data(), req.size());
            concatenated.insert(concatenated.end(),
                                std::begin(inner.bytes),
                                std::end(inner.bytes));
        }
        requests_hash_ = sha256_bytes32(concatenated.data(), concatenated.size());
    }

    // EIP-7685 validity: the recomputed requests_hash must match the
    // value declared in the block header. A mismatch means the block's
    // requests (deposits/withdrawals/consolidations) are invalid or the
    // declared hash is wrong — reject the block. Only meaningful for
    // Pectra+ (Prague/Osaka); the header omits requests_hash before
    // that fork, mirroring block_header.cpp's RLP gate.
    if (is_prague_or_later() &&
        requests_hash_ != consensus_.requests_hash()) {
        fatal("requests_hash mismatch (invalid block requests)");
    }
}

// ===== Private methods =====

size_t ZiskStateDB::account_row(const evmc::address& addr) const noexcept {
    return accounts_.index_of(addr);  // halts if the address has no row
}

size_t ZiskStateDB::storage_row(const evmc::address& addr,
                                const evmc::bytes32& key) const noexcept {
    const size_t idx = storages_.find(addr, key);
    if (idx == Storages::npos) {
        // Every slot the block loads is a row (an empty leaf if it doesn't
        // exist); one without is unproven, so halt.
        std::fprintf(stderr, "missing slot 0x");
        for (uint8_t b : addr.bytes) std::fprintf(stderr, "%02x", b);
        std::fprintf(stderr, " 0x");
        for (uint8_t b : key.bytes) std::fprintf(stderr, "%02x", b);
        std::fprintf(stderr, "\n");
        fatal("state key not in witness: storage slot");
    }
    return idx;
}

size_t ZiskStateDB::pending_row(const evmc::address& addr) const noexcept {
    return accounts_.contains(addr) ? accounts_.index_of(addr) : kMissingRow;
}

evmc_result ZiskStateDB::run_frame(const evmc_message* msg, const uint8_t* code,
                                   size_t code_size, evmc2_pre_execution* analysis) noexcept {
    const evmc_result r = vm2_->execute2(&vm2_->base, &evmc::Host::get_interface(),
                                         to_context(), active_revision(), msg, code,
                                         code_size, analysis);
    // The frame has returned: drop the pin acquired by analysis_for so the
    // cache may reuse this slot (a no-op for the uncached/nullptr path, e.g.
    // CREATE initcode). Safe because execute2 ran the whole frame + its
    // children synchronously, so the analysis is no longer referenced.
    cache_->release(analysis);
    // A frame that ends normally (success or revert) paid for its last
    // access; one that halts exceptionally may have halted on that charge.
    if (r.status_code == EVMC_SUCCESS || r.status_code == EVMC_REVERT) {
        bal_commit_pending();
    }
    bal_pending_ = kNoBalPending;
    return r;
}

void ZiskStateDB::bal_commit_pending() const noexcept {
    if (bal_pending_ != kNoBalPending) {
        // The access was paid for, so the account is in the BAL — and must
        // be a row.
        if (bal_pending_ == kMissingRow) fatal("state key not in witness: BAL account");
        accounts_.bal_access_at(bal_pending_);
        bal_pending_ = kNoBalPending;
    }
}

void ZiskStateDB::bal_load(const evmc::address& addr) noexcept {
    accounts_.bal_access_at(account_row(addr));
}

BlockAccessList::Slot& ZiskStateDB::bal_slot(size_t storage_idx) noexcept {
    auto& s = bal_->witness_slot(storages_.bal_id_at(storage_idx),
                                 storages_.position_at(storage_idx));
    bal_->access_slot(s);
    return s;
}

evmc::bytes32 ZiskStateDB::build_block_access_list_hash() noexcept {
    // EIP-7928 size limit: one item per account plus one per slot.
    const std::size_t items = bal_->accessed_accounts() + bal_->accessed_slots();
    if (items > consensus_.gas_limit() / kBalItemCost) {
        fatal("block access list exceeds the gas limit (BLOCK_ACCESS_LIST_GAS_LIMIT_EXCEEDED)");
    }

    // Walk every row in sorted order. The links come from the input, so
    // check them: addresses strictly increasing, each account's slots
    // strictly increasing and owned by it, and every row visited — which
    // makes the walk exactly the rows, in order. Every key the block loaded
    // is a row, so emitting the accessed ones gives the BAL.
    constexpr uint64_t kNoLink = Accounts::kNoLink;
    const uint64_t n_accounts = accounts_.size();
    const uint64_t n_storages = storages_.size();
    std::vector<const BlockAccessList::Slot*> slots;
    slots.reserve(bal_->accessed_slots());
    std::vector<BlockAccessList::Entry> entries;
    entries.reserve(bal_->accessed_accounts());
    uint64_t seen_accounts = 0;
    uint64_t seen_storages = 0;
    const evmc::address* prev_addr = nullptr;
    for (uint64_t row = accounts_.first_sorted(); row != kNoLink;
         row = accounts_.next_sorted_at(row)) {
        if (row >= n_accounts || ++seen_accounts > n_accounts) {
            fatal("BAL: bad account link");
        }
        const evmc::address& addr = accounts_.address_at(row);
        if (prev_addr != nullptr && std::memcmp(prev_addr->bytes, addr.bytes, 20) >= 0) {
            fatal("BAL: account links not strictly increasing");
        }
        prev_addr = &addr;

        const std::size_t first = slots.size();
        const evmc::bytes32* prev_key = nullptr;
        for (uint64_t s = accounts_.first_sorted_storage_at(row); s != kNoLink;
             s = storages_.next_sorted_at(s)) {
            if (s >= n_storages || ++seen_storages > n_storages) {
                fatal("BAL: bad storage link");
            }
            if (std::memcmp(storages_.address_at(s).bytes, addr.bytes, 20) != 0) {
                fatal("BAL: storage link leaves its account");
            }
            const evmc::bytes32& key = storages_.position_at(s);
            if (prev_key != nullptr && std::memcmp(prev_key->bytes, key.bytes, 32) >= 0) {
                fatal("BAL: storage links not strictly increasing");
            }
            prev_key = &key;
            const uint32_t id = storages_.bal_id_at(s);
            if (id == BlockAccessList::kNone || !bal_->slot(id).accessed) continue;
            BlockAccessList::Slot& sl = bal_->slot(id);
            bal_->close_slot(sl, storages_.value_at(s));
            slots.push_back(&sl);
        }

        if (!bal_->account(row).accessed) {
            if (slots.size() != first) fatal("BAL: slot accessed without its account");
            continue;
        }
        bal_->close_account(row, accounts_.balance_at(row), accounts_.nonce_at(row),
                            accounts_.code_hash_at(row));
        entries.push_back(BlockAccessList::Entry{
            &addr, &bal_->account(row),
            std::span<const BlockAccessList::Slot* const>{slots.data() + first,
                                                          slots.size() - first}});
    }
    if (seen_accounts != n_accounts || seen_storages != n_storages) {
        fatal("BAL: sorted links don't cover every row");
    }
    // Every accessed row was visited, so these hold by construction; keep
    // them as a cheap guard on the accessed-flag bookkeeping.
    if (entries.size() != bal_->accessed_accounts() || slots.size() != bal_->accessed_slots()) {
        fatal("BAL: accessed count mismatch");
    }
    if (std::getenv("ZEG_DUMP_BAL") != nullptr) bal_->dump(entries, contracts_);  // DEBUG
    bal_rlp_ = bal_->encode(entries, contracts_);
    return keccak256_bytes32(bal_rlp_.data(), bal_rlp_.size());
}

void ZiskStateDB::transfer_value(const evmc::address& from,
                                 const evmc::address& to,
                                 const evmc::uint256be& value) noexcept {
    const size_t from_idx = account_row(from);
    const size_t to_idx   = account_row(to);

    // Self-transfer is a no-op (debit and credit cancel). Without this
    // guard the two `set_balance_at` calls below would target the same
    // slot — the second overwrites the first and leaves the account
    // net-credited by `value` instead of unchanged.
    if (from_idx == to_idx) {
        return;
    }

    journal_.log_balance(from_idx, accounts_.balance_at(from_idx),
                         accounts_.last_tx_idx_at(from_idx));
    journal_.log_balance(to_idx,   accounts_.balance_at(to_idx),
                         accounts_.last_tx_idx_at(to_idx));

    const auto from_u = intx::be::load<intx::uint256>(accounts_.balance_at(from_idx));
    const auto to_u   = intx::be::load<intx::uint256>(accounts_.balance_at(to_idx));
    const auto v_u    = intx::be::load<intx::uint256>(value);

    // The EVM gated the call on `from_u >= v_u`; we don't re-check.
    accounts_.set_balance_at(from_idx,
                             intx::be::store<evmc::uint256be>(from_u - v_u),
                             tx_counter_);
    accounts_.set_balance_at(to_idx,
                             intx::be::store<evmc::uint256be>(to_u   + v_u),
                             tx_counter_);
    emit_transfer_log(from, to, value);
}

void ZiskStateDB::emit_transfer_log(const evmc::address& from,
                                    const evmc::address& to,
                                    const evmc::uint256be& value) noexcept {
    if (!is_amsterdam_or_later() || from == to ||
        intx::be::load<intx::uint256>(value) == 0) {
        return;
    }
    evmc::bytes32 topics[3] = {kTransferEventTopic, {}, {}};
    std::memcpy(topics[1].bytes + 12, from.bytes, 20);
    std::memcpy(topics[2].bytes + 12, to.bytes, 20);
    emit_log(kSystemAddress, value.bytes, sizeof(value.bytes), topics, 3);
}

evmc::Result ZiskStateDB::call_create(const evmc_message& msg,
                                      Checkpoint cp) noexcept {
    // The EVM hands us the init code either via msg.code (modern evmc
    // convention for nested calls) or via msg.input_data (the legacy
    // convention some flows still use). Use whichever is set.
    const uint8_t*    init_code = msg.code != nullptr ? msg.code : msg.input_data;
    const std::size_t init_size = msg.code != nullptr ? msg.code_size : msg.input_size;

    // 1. Derive the new contract address. Sender's nonce *before* the
    //    create-time increment is the input to the CREATE hash.
    const size_t   sender_idx       = account_row(msg.sender);
    const uint64_t sender_nonce_pre = accounts_.nonce_at(sender_idx);

    // EIP-2681: a CREATE/CREATE2 whose sender's nonce is already at the
    // u64 max can't bump it (would overflow) and must fail as a "light"
    // failure — no state touched at all (no address warming, no nonce
    // change), gas_left unchanged. Matches revm's frame.rs:
    // `if !caller_info.bump_nonce() { return return_error(...) }`,
    // checked before the new address is even computed/warmed. Without
    // this, `sender_nonce_pre + 1` below silently wraps to 0 and the
    // create proceeds as if nothing were wrong.
    if (sender_nonce_pre == std::numeric_limits<uint64_t>::max()) {
        return evmc::Result{EVMC_SUCCESS, msg.gas, 0, nullptr, 0,
                            {.left = msg.state_gas}};
    }

    // The VM derives the new address (CREATE: sender + nonce; CREATE2:
    // sender + salt + keccak(init code)) and passes it as the recipient.
    const auto& new_addr = msg.recipient;

    // 2. Bump sender nonce (journaled).
    journal_.log_nonce(sender_idx, sender_nonce_pre,
                       accounts_.last_tx_idx_at(sender_idx));
    accounts_.set_nonce_at(sender_idx, sender_nonce_pre + 1, tx_counter_);

    // EIP-2929: the new contract address is added to accessed_addresses
    // as part of looking it up for the collision check below — warmed
    // unconditionally, regardless of whether the create then succeeds
    // or fails (collision, init-code revert/OOG, EIP-2 deposit OOG).
    // Journaled *before* `cp_after_bump` (see note below) so the
    // warmth survives a local CREATE-internal failure, mirroring how
    // the sender-nonce bump does. EIP-6780 same-tx-destruct
    // eligibility is intentionally NOT granted here — that only
    // applies to a successfully created account (see step 3 below).
    const size_t na_idx = account_row(new_addr);
    accounts_.bal_access_at(na_idx);  // EIP-7928: loaded for the collision check
    if (!accounts_.is_warm_at(na_idx, tx_counter_)) {
        journal_.log_account_warm(na_idx, accounts_.last_tx_idx_at(na_idx));
    }
    accounts_.mark_touched_at(na_idx, tx_counter_);

    // 2'. Per EVM spec (post-EIP-161 / EIP-684), the sender's nonce
    //     bump above persists through every CREATE-internal failure
    //     mode below — collision, init-code revert/OOG, EIP-2 code-
    //     deposit OOG. So we anchor our local rollbacks on a fresh
    //     checkpoint taken AFTER the bump rather than on `cp` (which
    //     pre-dates it). The caller's `cp` still subsumes the bump,
    //     so an outer-frame revert (parent CALL/CREATE reverts, tx
    //     reverts) correctly unbumps. Miss-handled previously: block
    //     25199793 tx 337 — CREATE -> inner CREATE2 that failed left
    //     the inner-CREATE2 sender's nonce at 1 instead of 2. The
    //     address-warming above is anchored the same way, for the
    //     same reason (fixture CreateAddressWarmAfterFail.json).
    const auto cp_after_bump = checkpoint();

    // 3. EIP-684 collision check + initialize the new account (nonce
    //    = 1 + value transfer). Returns false on collision.
    if (!init_create_account(new_addr, msg)) {
        rollback(cp_after_bump);
        return evmc::Result{EVMC_FAILURE, 0, 0, nullptr, 0,
                            {.left = msg.state_gas}};
    }

    // EIP-6780: mark the new index as "created this tx" so a later
    // SELFDESTRUCT from this contract fully destroys it (instead of
    // just transferring balance). Success-only — unlike the warming
    // above, this must NOT survive a failed create.
    created_this_tx_idx_.insert(na_idx);

    // 4. Execute the init code with the new address as the recipient.
    evmc_message create_msg = msg;
    create_msg.recipient    = new_addr;
    // `msg.input_data`/`msg.input_size` hold the init code itself (evmone's
    // CREATE/CREATE2 message convention — see init_code/init_size above).
    // The init code's own execution must see EMPTY calldata (CALLDATASIZE
    // == 0): a CREATE-family message never carries separate constructor
    // arguments the way a CALL carries calldata. Left uncleared, copying
    // `msg` verbatim leaked the init-code length as bogus calldata,
    // matching evmone's own reference Host::create() (test/state/host.cpp),
    // which does the same `create_msg.input_data = nullptr` clear.
    create_msg.input_data   = nullptr;
    create_msg.input_size   = 0;
    // CREATE initcode runs once and its transient bytes aren't a stable cache
    // key, so no pre-analysis (pre == nullptr ⇒ plain execute).
    auto result = evmc::Result{run_frame(&create_msg, init_code, init_size, nullptr)};
    if (result.status_code != EVMC_SUCCESS) {
        rollback(cp_after_bump);
        return result;
    }

    // EIP-170 (Spurious Dragon): deployed code cannot exceed
    // MAX_CODE_SIZE (24576 B; 65536 B from Amsterdam, EIP-7954).
    // Checked BEFORE EIP-3541 below, matching
    // reth/geth's ordering. Every fork this guest targets (Berlin+)
    // postdates Spurious Dragon, so no fork gate is needed. On failure
    // all gas allocated to this CREATE is burned (gas_left=0) rather
    // than only refusing the per-byte deposit cost — the create-vs-OOG
    // gap this closes: codesizeOOGInvalidSize, createCodeSizeLimit,
    // create2CodeSizeLimit, CreateAddressWarmAfterFail's *_code_too_big
    // cases, createLargeResult's *_RETURN_HUGE/TOOBIG cases, and
    // CREATE_ContractRETURNBigOffset.
    if (result.output_size > max_code_size()) {
        rollback(cp_after_bump);
        return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0,
                            {.left = msg.state_gas}};
    }

    // EIP-3541 (London+): contracts cannot have deployed code that
    // starts with the 0xef byte (pre-London, e.g. Berlin, it is valid
    // code — test_create_one_byte deploys `0xef`). EIP-7702 extends this for the
    // delegation-designation prefix 0xef0100 specifically — CREATE/
    // CREATE2 must reject init code that RETURNS code starting with
    // these bytes (otherwise the deployed contract would be
    // indistinguishable from a 7702-installed delegation indicator).
    // Reth rejects such CREATEs; fixtures
    // test_creating_delegation_designation_contract and
    // test_deploying_delegation_designation_contract verify this.
    if (is_london_or_later() && result.output_size > 0 &&
        result.output_data[0] == 0xef) {
        rollback(cp_after_bump);
        return evmc::Result{EVMC_CONTRACT_VALIDATION_FAILURE, 0, 0, nullptr, 0,
                            {.left = msg.state_gas}};
    }

    // Code deposit, charged AFTER the init code's RETURN from its
    // remaining gas. If the frame can't cover it, the whole CREATE fails
    // (per EIP-2 / Homestead+ semantics).
    if (!charge_code_deposit(result, is_amsterdam_or_later())) {
        rollback(cp_after_bump);
        return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0,
                            {.left = msg.state_gas}};
    }

    // 5. Register the deployed code on the new account. A *successful*
    //    CREATE/CREATE2 must not propagate the init code's RETURN payload
    //    as call return-data (only a REVERT's payload does) — build a
    //    fresh Result with empty output so RETURNDATASIZE reads 0 to the
    //    caller afterward, matching evmone's own reference Host::create()
    //    (test/state/host.cpp), which does the same on its success path.
    register_deployed_code(new_addr, result);
    return evmc::Result{result.status_code, result.gas_left, result.gas_refund,
                        nullptr, 0, result.state_gas};
}

bool ZiskStateDB::address_has_storage(const evmc::address& addr) const noexcept {
    for (size_t i : storages_.slots_of(addr)) {
        if (!is_zero_value(storages_.value_at(i))) return true;
    }
    return false;
}

bool ZiskStateDB::has_block_start_storage(size_t idx) const noexcept {
    if (storage_wiped_idx_.count(idx) != 0) return false;
    // The block-start storage root, recorded by the old-root walk. A subtree
    // of absent (empty) slot leaves hashes to the empty root, so this — not
    // the subtree's node type — says whether storage existed. Rows appended
    // at run time have none.
    return !accounts_.block_start_storage_empty_at(idx);
}

bool ZiskStateDB::init_create_account(const evmc::address& new_addr,
                                      const evmc_message&  msg) noexcept {
    // EIP-684 collision check (EIP-7610 clarifies storage also counts).
    // A brand-new contract address is a row too (an empty leaf). It must
    // look empty (nonce == 0, code_hash == EMPTY, and no non-zero storage).
    //
    // DELIBERATE DEVIATION (audit #20): we treat non-empty storage at the
    // target as a collision (EIP-7610). execution-specs v21 and revm currently
    // check only nonce and code, NOT storage. The cases differ only for a CREATE
    // whose target address already has storage but no nonce/code — which
    // requires grinding a specific 160-bit address, so no mainnet/Sepolia block
    // reaches it today. Revisit/align if execution-specs adopts EIP-7610.
    const size_t new_idx = account_row(new_addr);
    if (accounts_.nonce_at(new_idx) != 0 ||
        accounts_.code_hash_at(new_idx) != EMPTY_CODE_HASH ||
        address_has_storage(new_addr) || has_block_start_storage(new_idx)) {
        return false;
    }

    // Initialize the new account: nonce = 1 (post EIP-161) and the
    // value transfer. Both go through the journal so a revert unwinds
    // them.
    journal_.log_nonce(new_idx, accounts_.nonce_at(new_idx),
                       accounts_.last_tx_idx_at(new_idx));
    accounts_.set_nonce_at(new_idx, 1, tx_counter_);

    if (intx::be::load<intx::uint256>(msg.value) != 0) {
        transfer_value(msg.sender, new_addr, msg.value);
    }
    return true;
}

void ZiskStateDB::register_deployed_code(const evmc::address& new_addr,
                                         const evmc::Result&  result) noexcept {
    // The Contracts table is consulted lazily by `code()` /
    // `copy_code()` / `get_code_size()` only if the new contract is
    // read later in this block.
    const size_t new_idx = accounts_.index_of(new_addr);
    const auto deployed_hash =
        keccak256_bytes32(result.output_data, result.output_size);
    // Register the deployed code in the Contracts table so subsequent
    // CALLs in this tx (and later txs) can resolve it by hash. The
    // prover's prestate diff omits CREATE-and-then-SELFDESTRUCT (or
    // otherwise-empty-by-tx-end) contracts even when they're CALL'd
    // mid-tx (see block 25193032), so we can't rely on the input
    // stream having pre-included this code. Insert is idempotent.
    if (result.output_size > 0) {
        contracts_.insert(deployed_hash, result.output_data, result.output_size);
    }
    const char* trace_env = std::getenv("ZEG_TRACE_TX");
    if (trace_env != nullptr &&
        tx_counter_ == static_cast<uint64_t>(std::atoi(trace_env) + 1)) {
        std::fprintf(stderr, "DBG deployed addr=0x");
        for (int i = 0; i < 20; ++i) std::fprintf(stderr, "%02x", new_addr.bytes[i]);
        std::fprintf(stderr, " hash=0x");
        for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", deployed_hash.bytes[i]);
        std::fprintf(stderr, " size=%zu code=0x", result.output_size);
        for (size_t i = 0; i < result.output_size && i < 60; ++i)
            std::fprintf(stderr, "%02x", result.output_data[i]);
        std::fprintf(stderr, "\n");
    }
    journal_.log_code_hash(new_idx, accounts_.code_hash_at(new_idx),
                           accounts_.last_tx_idx_at(new_idx));
    accounts_.set_code_hash_at(new_idx, deployed_hash, tx_counter_);
}

void ZiskStateDB::pre_execute_block() noexcept {
    // EIP-7928 (Amsterdam): start the block-level access list. Index 0
    // covers the pre-execution system calls below.
    if (is_amsterdam_or_later()) {
        bal_ = std::make_unique<BlockAccessList>(accounts_.capacity());
        bal_->set_index(0);
        accounts_.set_block_access_list(bal_.get());
    }

    // --- Block-level tx_context ---
    //
    // Persists across every tx in this block; process_transactions
    // later overwrites the per-tx fields (tx_origin, tx_gas_price, …)
    // without touching these.
    {
        evmc_tx_context ctx{};
        ctx.block_coinbase    = consensus_.beneficiary();
        ctx.block_number      = static_cast<int64_t>(consensus_.number());
        ctx.block_timestamp   = static_cast<int64_t>(consensus_.timestamp());
        ctx.block_gas_limit   = static_cast<int64_t>(consensus_.gas_limit());
        // EIP-7843 (Amsterdam) SLOTNUM; zero before Amsterdam.
        ctx.block_slot_number = consensus_.slot_number();
        // EIP-4399 (Paris): opcode 0x44 (DIFFICULTY pre-Paris, PREVRANDAO
        // Paris+) reads this same tx_context field either way — the HOST
        // decides which ConsensusInfo value it holds. Pre-Paris blocks
        // must see the real PoW difficulty; using prev_randao() there
        // returns an unrelated field's bytes (mixHash-shaped, not the
        // difficulty), which corrupted any test scanning the DIFFICULTY
        // opcode's raw output (test_scenarios' DIFFICULTY_debug cluster).
        ctx.block_prev_randao = is_paris_or_later() ? consensus_.prev_randao()
                                                     : consensus_.difficulty();
        ctx.chain_id          = intx::be::store<evmc::uint256be>(
                                    intx::uint256{kChainId});
        ctx.block_base_fee    = consensus_.base_fee_per_gas();
        // EIP-4844: blob_base_fee = fake_exponential(1, excess_blob_gas,
        //   BLOB_BASE_FEE_UPDATE_FRACTION). The fraction is per-block (carried
        //   in ConsensusInfo) since it differs per blob schedule — Cancun
        //   3338477, Prague/Osaka 5007716, mainnet BPO forks higher — and
        //   mainnet-Osaka vs EEST-Osaka share fork_id but not the schedule.
        ctx.blob_base_fee     = intx::be::store<evmc::uint256be>(
            fake_exponential(kMinBaseFeePerBlobGas,
                             consensus_.excess_blob_gas(),
                             consensus_.blob_base_fee_update_fraction()));
        set_tx_context(ctx);
    }

    // --- EIP-4788: parent beacon block root predeploy ---
    //
    // Write the parent's beacon block root into the beacon roots
    // predeploy. The contract's storage maps timestamp →
    // parent_beacon_block_root in an 8191-slot ring buffer so the
    // CL/EL can prove past beacon roots.
    //
    // EIP-4788 activates in Cancun. Skip for pre-Cancun blocks
    // (Berlin/London/Paris/Shanghai) — the predeploy isn't installed
    // before Cancun, and an unconditional system_call would fatal at
    // accounts_.index_of for the predeploy address. Hit by every
    // Berlin-pinned EEST Osaka EIP-7883 modexp backward-compat test.
    if (is_cancun_or_later()) {
        const auto& root = consensus_.parent_beacon_block_root();
        (void)system_call(kBeaconRootsAddress,
                          std::span<const uint8_t>{root.bytes, 32});
    }

    // --- EIP-2935: parent block hash history ---
    //
    // Write the parent's block hash into the history storage contract.
    // The contract stores hashes indexed by (block_number) so
    // BLOCKHASH can reach further back than the opcode's 256-block
    // window via the predeploy.
    //
    // NOTE: `consensus_.parent_hash()` is the parent's STATE ROOT in
    // this guest's binary format (see get_block_hash() above) — NOT
    // the parent's block hash. The actual block hash lives in
    // `previous_blocks_[0]` (the parent), where the EVM BLOCKHASH
    // opcode reads it. Passing parent_hash() here was a silent bug:
    // the call would succeed but the contract would store the wrong
    // value, producing a state-trie divergence the test only catches
    // via post-state-root mismatch.
    //
    // EIP-2935 activates in Prague. Skip it for Cancun blocks (which
    // we may encounter as pre-fork blocks in mixed-fork EEST fixtures).
    // field_count==0 (old manifests) is treated as Pectra by default
    // — preserves mainnet replay behavior.
    if (is_prague_or_later()) {
        const auto parent_block_hash = previous_blocks_.hash(0);
        (void)system_call(kHistoryStorageAddress,
                          std::span<const uint8_t>{parent_block_hash.bytes, 32});
    }
}

void ZiskStateDB::process_transactions(const Transactions& transactions) noexcept {
    for (size_t i = 0; i < transactions.size(); ++i) {
        // Bump the tx counter BEFORE any Storages access — so the
        // very first SLOAD/SSTORE/access in this tx sees a fresh
        // tx_idx and trips Storages::mark_touched_at's snapshot
        // path. Starts the first tx at counter 1 (> 0 sentinel).
        // Transient storage (EIP-1153) is also reset per-tx.
        // EIP-6780: the "created this tx" set is per-tx; reset here
        // so SELFDESTRUCT in the new tx only fully-destroys accounts
        // CREATEd by this tx, not by any prior one.
        ++tx_counter_;
        // Per-tx arena (zeg/tx_arena.hpp): the journal (no checkpoint
        // spans a tx), the transient map and every evmone call output of
        // the previous tx are dead. Drop the containers' storage, reclaim
        // the arena, and only then allocate their storage for this tx.
        journal_.release();
        transient_.release();
        tx_arena_reset();
        journal_.init();
        transient_.init();
        created_this_tx_idx_.clear();
        // pending_destruct_ is also per-tx — `apply_pending_destructs`
        // at the END of the previous iteration drained it, so this
        // clear is just a paranoia guard (also handles tx 0).
        pending_destruct_.clear();

        const auto& tx = transactions.at(i);
        if (bal_) bal_->set_index(static_cast<uint32_t>(i + 1));  // EIP-7928

        // EIP-2929 / EIP-3651 / EIP-2930 / EIP-7702 pre-warming.
        // Marking these warm BEFORE the EVM starts means the first
        // access by the EVM charges WARM cost (100) instead of
        // COLD (2600 for accounts, 2100 for slots).
        pre_warm_for_tx(tx);

        // Push the receipt for this tx up front. emit_log appends to
        // tx_receipts_.back().logs during execution; finalize_receipt
        // fills status / bloom / cumGas at the end of the iteration.
        tx_receipts_.emplace_back().tx_type = tx.type();

        // Backing storage for the blob-hashes array pointed to by the
        // per-tx tx_context. Must outlive the execute2 call below — the
        // ctx field is a raw pointer into this vector.
        std::vector<evmc::bytes32> blob_hashes;
        set_tx_context(build_per_tx_context(tx, blob_hashes));

        // Pre-EVM accounting (NOT journaled — survives EVM revert).
        const size_t  sender_idx    = account_row(tx.sender());
        const int64_t intrinsic_gas = apply_pre_evm_accounting(tx, sender_idx);

        // The tx's gas after intrinsic: regular gas, and the EIP-8037
        // reservoir (the gas limit above the EIP-7825 cap, Amsterdam).
        TxGas g{static_cast<int64_t>(tx.gas_limit()) - intrinsic_gas - tx_state_gas_limit_,
                {.left = tx_state_gas_limit_}};

        // EIP-7702 authorization list (Type-4 only). Returns the
        // 12500-per-pre-existing-signer refund that folds into the
        // post-EVM refund cap. Amsterdam (EIP-2780) charges `g` instead;
        // if the authorizations or the first frame's charges run out of
        // gas, the whole runtime phase from `cp_runtime` is undone
        // (delegations included) and the tx is an out-of-gas halt.
        const auto    cp_runtime  = checkpoint();
        const int64_t auth_refund = apply_authorization_list(tx, sender_idx, g);

        // Checkpoint AFTER the upfront accounting + EIP-7702 auths so
        // none of those are rolled back on EVM revert. State changes
        // made inside the checkpoint (value transfer, EVM writes) are
        // undone if the frame fails.
        const auto cp     = checkpoint();
        std::fprintf(stderr, "TX %zu START\n", i);
        auto       result = execute_top_level_frame(tx, sender_idx, g);
        if (g.runtime_oog) {
            rollback(cp_runtime);
        } else if (result.status_code != EVMC_SUCCESS) {
            rollback(cp);
        }

        const auto used = settle_tx_gas(tx, result, sender_idx, auth_refund);
        std::fprintf(stderr, "TX %zu gas_used=%llu status=%d\n",
                     i, (unsigned long long)used.gas_used,
                     (int)result.status_code);
        finalize_receipt(result, used);

        // Apply deferred SELFDESTRUCT clears now that the tx has
        // committed. Per Yellow Paper, destruction happens at the
        // end of the TRANSACTION, not at the SELFDESTRUCT opcode.
        // See pending_destruct_ in the header for the rationale.
        apply_pending_destructs();
    }
    bal_tx_count_ = static_cast<uint32_t>(transactions.size());
}

// ----- per-tx pipeline helpers ----------------------------------------------

void ZiskStateDB::pre_warm_for_tx(const Transactions::View& tx) noexcept {
    auto warm_addr = [&](const evmc::address& a) {
        // Precompiles are inherently warm — no Accounts entry needed.
        if (evmone::state::is_precompile(active_revision(), a)) {
            return;
        }
        // Warming is not a load: an address the block never loads may have
        // no row. Not journaled — pre-warming is tx-initial.
        if (accounts_.contains(a)) {
            accounts_.mark_touched_at(accounts_.index_of(a), tx_counter_);
        } else {
            warm_keys_.set_account(a, tx_counter_);
        }
    };

    // tx.origin (EIP-2929) + coinbase (EIP-3651, Shanghai+) + tx.to.
    warm_addr(tx.sender());
    if (is_shanghai_or_later()) {
        warm_addr(consensus_.beneficiary());
    }
    if (tx.to() != nullptr) {
        warm_addr(*tx.to());
    }

    // EIP-2930 access list: [[addr, [slot_keys...]], ...] — present on
    // Type-1 (AccessList), Type-2 (DynamicFee), Type-3 (Blob), Type-4
    // (SetCode), Type-5 (Osaka initcode) txs. Legacy txs have no list.
    const auto access_rlp = tx.access_list_rlp();
    if (!access_rlp.empty()) {
        const auto outer = rlp::decode_item(access_rlp);
        if (outer.kind != rlp::ItemKind::List) {
            fatal("access_list_rlp: not a list");
        }
        rlp::ListIter it{outer.payload};
        while (it.has_next()) {
            const auto entry = it.next();
            if (entry.kind != rlp::ItemKind::List) {
                fatal("access_list entry not a list");
            }
            rlp::ListIter eit{entry.payload};
            if (!eit.has_next()) fatal("access_list entry missing addr");
            const auto addr_item = eit.next();
            if (addr_item.kind != rlp::ItemKind::String ||
                addr_item.payload.size() != 20) {
                fatal("access_list addr not 20-byte string");
            }
            evmc::address a;
            std::memcpy(a.bytes, addr_item.payload.data(), 20);
            warm_addr(a);

            if (!eit.has_next()) fatal("access_list entry missing keys");
            const auto keys_item = eit.next();
            if (keys_item.kind != rlp::ItemKind::List) {
                fatal("access_list keys not a list");
            }
            rlp::ListIter kit{keys_item.payload};
            while (kit.has_next()) {
                const auto k = kit.next();
                if (k.kind != rlp::ItemKind::String ||
                    k.payload.size() != 32) {
                    fatal("access_list slot key not 32-byte string");
                }
                evmc::bytes32 slot;
                std::memcpy(slot.bytes, k.payload.data(), 32);
                const size_t sidx = storages_.find(a, slot);
                if (sidx == Storages::npos) {
                    // A slot the block never loads may have no row.
                    warm_keys_.set_slot(a, slot, tx_counter_);
                    continue;
                }
                storages_.mark_touched_at(sidx, tx_counter_);
            }
        }
    }

    // EIP-7702 authority addresses are pre-warmed during
    // apply_authorization_list (which is called right after this
    // helper but before EVM execution — also OK).
}

evmc_tx_context ZiskStateDB::build_per_tx_context(
        const Transactions::View&   tx,
        std::vector<evmc::bytes32>& blob_hashes) noexcept {
    using TxType = Transactions::Type;

    auto ctx      = tx_context_;
    ctx.tx_origin = tx.sender();
    // Effective gas price per EIP-1559:
    //   legacy / access-list:  gas_price (no separate priority field)
    //   typed (1559+):         min(max_fee_per_gas,
    //                              base_fee + max_priority_fee_per_gas)
    // The GASPRICE opcode returns this value; mis-computing it changes
    // execution paths in contracts that branch on `tx.gasprice`.
    if (tx.type() == TxType::Legacy || tx.type() == TxType::AccessList) {
        ctx.tx_gas_price = tx.gas_price();
    } else {
        const auto base_fee = intx::be::load<intx::uint256>(
            consensus_.base_fee_per_gas());
        const auto priority = intx::be::load<intx::uint256>(
            tx.max_priority_fee_per_gas());
        const auto max_fee  = intx::be::load<intx::uint256>(
            tx.max_fee_per_gas());
        const auto eff = (base_fee + priority < max_fee)
                             ? (base_fee + priority)
                             : max_fee;
        ctx.tx_gas_price = intx::be::store<evmc::uint256be>(eff);
    }

    // EIP-4844 blob_hashes — only Type-3 carries them; other types
    // leave the pair zeroed.
    ctx.blob_hashes       = nullptr;
    ctx.blob_hashes_count = 0;
    if (tx.type() == TxType::Blob) {
        const auto raw   = tx.blob_versioned_hashes_rlp();
        const auto outer = rlp::decode_item(raw);
        if (outer.kind != rlp::ItemKind::List) {
            fatal("blob_versioned_hashes is not an RLP list");
        }
        rlp::ListIter it{outer.payload};
        while (it.has_next()) {
            const auto item = it.next();
            if (item.kind != rlp::ItemKind::String ||
                item.payload.size() != 32) {
                fatal("blob_versioned_hashes: expected 32-byte string");
            }
            evmc::bytes32 h;
            std::memcpy(h.bytes, item.payload.data(), 32);
            blob_hashes.push_back(h);
        }
        ctx.blob_hashes       = blob_hashes.data();
        ctx.blob_hashes_count = blob_hashes.size();
        // Accumulate the block-level blob_gas_used field (EIP-4844).
        // The per-tx fee debit happens in apply_pre_evm_accounting;
        // this is just the running header total.
        blob_gas_used_ += blob_hashes.size() * kGasPerBlob;
    }

    return ctx;
}

int64_t ZiskStateDB::check_transaction(const Transactions::View& tx,
                                       size_t sender_idx) noexcept {
    using TxType = Transactions::Type;
    const TxType type = tx.type();

    // Tx type must be active at this fork (EIP-1559 / 4844 / 7702).
    // EIP-7873 (type 5) isn't scheduled in any fork.
    if ((type == TxType::DynamicFee && !is_london_or_later()) ||
        (type == TxType::Blob && !is_cancun_or_later()) ||
        (type == TxType::SetCode && !is_prague_or_later()) ||
        type == TxType::Osaka) {
        fatal("tx type not active at this fork");
    }
    // Chain id (execution-specs recover_sender): typed and EIP-155
    // legacy txs must carry this chain's id; pre-EIP-155 legacy txs
    // (v = 27 / 28) carry none and stay valid.
    if (tx.chain_id() != kChainId &&
        !(type == TxType::Legacy && tx.v_or_y_parity() < 35)) {
        fatal("tx chain_id mismatch");
    }

    // ----- validate_transaction -----
    // gas_limit must cover the intrinsic gas and (EIP-7623, Prague) the
    // calldata floor.
    const int64_t intrinsic_gas =
        compute_intrinsic_gas(tx, active_revision(), &tx_floor_gas_);
    const int64_t min_gas = is_prague_or_later()
                                ? std::max(intrinsic_gas, tx_floor_gas_)
                                : intrinsic_gas;
    // EIP-8037 (Amsterdam): gas above the EIP-7825 cap is the state-gas
    // reservoir, so intrinsic gas and the floor must fit under the cap.
    const uint64_t gas_limit = tx.gas_limit();
    const uint64_t state_gas_limit =
        (is_amsterdam_or_later() && gas_limit > kMaxTxGasLimit) ? gas_limit - kMaxTxGasLimit
                                                                : 0;
    if (gas_limit - state_gas_limit < static_cast<uint64_t>(min_gas)) {
        fatal("tx gas_limit below intrinsic gas");
    }
    // EIP-7825 (Osaka): tx gas limit cap. Amsterdam (EIP-8037) applies it
    // to the regular gas only and caps the whole gas limit at
    // TX_MAX_TOTAL_GAS_LIMIT instead (execution-specs; EEST
    // test_tx_total_gas_limit_cap).
    if (is_amsterdam_or_later() ? gas_limit > kMaxTxTotalGasLimit
                                : is_osaka_or_later() && gas_limit > kMaxTxGasLimit) {
        fatal("tx gas_limit exceeds cap");
    }
    // EIP-2681: nonce < 2^64 - 1.
    if (tx.nonce() == UINT64_MAX) {
        fatal("tx nonce at maximum");
    }
    // EIP-3860: creation tx init code <= 2 * MAX_CODE_SIZE (EIP-7954
    // raises MAX_CODE_SIZE in Amsterdam).
    if (tx.to() == nullptr && is_shanghai_or_later() &&
        tx.data().size() > max_initcode_size()) {
        fatal("tx init code exceeds size limit");
    }

    // ----- check_transaction -----
    // The tx must fit in the block's remaining gas (the counters cover
    // the txs before this one). Amsterdam (EIP-8037) checks each block
    // dimension: the capped gas limit against the regular gas left, the
    // full gas limit against the state gas left.
    if (is_amsterdam_or_later()) {
        if (std::min<uint64_t>(gas_limit, kMaxTxGasLimit) >
                consensus_.gas_limit() - block_regular_gas_used_ ||
            gas_limit > consensus_.gas_limit() - block_state_gas_used_) {
            fatal("tx gas_limit exceeds block gas available");
        }
    } else if (gas_limit > consensus_.gas_limit() - cumulative_gas_used_) {
        fatal("tx gas_limit exceeds block gas available");
    }
    tx_state_gas_limit_ = static_cast<int64_t>(state_gas_limit);

    const auto base_fee =
        intx::be::load<intx::uint256>(consensus_.base_fee_per_gas());
    const bool legacy_fee = type == TxType::Legacy || type == TxType::AccessList;
    const auto fee_cap = intx::be::load<intx::uint256>(
        legacy_fee ? tx.gas_price() : tx.max_fee_per_gas());
    if (!legacy_fee &&
        fee_cap < intx::be::load<intx::uint256>(tx.max_priority_fee_per_gas())) {
        fatal("tx max_priority_fee_per_gas above max_fee_per_gas");
    }
    if (fee_cap < base_fee) {
        fatal("tx fee cap below base fee");
    }
    // 512-bit: the fee fields are arbitrary 256-bit values and the
    // spec's sums are unbounded.
    intx::uint512 max_cost = intx::umul(intx::uint256{tx.gas_limit()}, fee_cap);

    if (type == TxType::Blob) {
        if (tx_context_.blob_hashes_count == 0) {
            fatal("blob tx without blobs");
        }
        // EIP-7594 (Osaka): blob count per tx.
        if (is_osaka_or_later() && tx_context_.blob_hashes_count > kMaxBlobsPerTx) {
            fatal("blob tx exceeds blob count limit");
        }
        for (size_t i = 0; i < tx_context_.blob_hashes_count; ++i) {
            if (tx_context_.blob_hashes[i].bytes[0] != kVersionedHashVersionKzg) {
                fatal("blob versioned hash has wrong version");
            }
        }
        // Block blob gas, already including this tx (build_per_tx_context).
        if (blob_gas_used_ > consensus_.max_blob_gas_per_block()) {
            fatal("block blob gas exceeds max");
        }
        const auto blob_fee_cap =
            intx::be::load<intx::uint256>(tx.max_fee_per_blob_gas());
        if (blob_fee_cap < intx::be::load<intx::uint256>(tx_context_.blob_base_fee)) {
            fatal("tx max_fee_per_blob_gas below blob base fee");
        }
        max_cost += intx::umul(
            intx::uint256{tx_context_.blob_hashes_count * kGasPerBlob}, blob_fee_cap);
    }
    if ((type == TxType::Blob || type == TxType::SetCode) && tx.to() == nullptr) {
        fatal("blob / set-code tx cannot create a contract");
    }
    if (type == TxType::SetCode && tx.num_authorizations() == 0) {
        fatal("set-code tx with empty authorization list");
    }

    if (tx.nonce() != accounts_.nonce_at(sender_idx)) {
        fatal("tx nonce mismatch");
    }
    // The sender must cover the MAXIMUM fee plus the value. The value
    // itself is moved later by `transfer_value`; without the `value`
    // term the debit wraps mod 2^256 and mints ether.
    max_cost += intx::be::load<intx::uint256>(tx.value());
    if (intx::uint512{intx::be::load<intx::uint256>(accounts_.balance_at(sender_idx))} <
        max_cost) {
        fatal("tx sender balance below upfront cost");
    }

    // EIP-3607: the sender must not have code, except (Prague+) an
    // EIP-7702 delegation designator (0xef0100 || address).
    const auto sender_code_hash = accounts_.code_hash_at(sender_idx);
    if (sender_code_hash != EMPTY_CODE_HASH) {
        const auto& c = contracts_.by_hash(sender_code_hash);
        const bool delegation = is_prague_or_later() && c.code_size == 23 &&
                                c.code[0] == 0xef && c.code[1] == 0x01 &&
                                c.code[2] == 0x00;
        if (!delegation) {
            fatal("tx sender has code");
        }
    }
    return intrinsic_gas;
}

int64_t ZiskStateDB::apply_pre_evm_accounting(const Transactions::View& tx,
                                              size_t sender_idx) noexcept {
    using TxType = Transactions::Type;

    const int64_t intrinsic_gas = check_transaction(tx, sender_idx);

    // EIP-161 / YP §6: sender nonce += 1, then debit upfront gas
    // (gas_limit × eff_gas_price + blob_gas × blob_base_fee). The
    // blob portion is burned. These changes are kept even if the EVM
    // frame reverts, matching mainnet semantics.
    accounts_.set_nonce_at(sender_idx, accounts_.nonce_at(sender_idx) + 1,
                           tx_counter_);

    const auto eff_gas_price_u =
        intx::be::load<intx::uint256>(tx_context_.tx_gas_price);
    auto upfront_u = intx::uint256{tx.gas_limit()} * eff_gas_price_u;

    // EIP-4844 blob gas charge for Type-3 txs. Each blob costs
    // kGasPerBlob blob-gas; the per-gas price is blob_base_fee
    // (already computed in pre_execute_block and stored in
    // tx_context_). Burned, not paid to coinbase.
    if (tx.type() == TxType::Blob) {
        const auto blob_gas_u =
            intx::uint256{tx_context_.blob_hashes_count * kGasPerBlob};
        const auto blob_fee_u =
            intx::be::load<intx::uint256>(tx_context_.blob_base_fee);
        upfront_u += blob_gas_u * blob_fee_u;
    }

    // No overflow / underflow: check_transaction bounded this by the
    // balance (eff_gas_price <= fee cap, blob_base_fee <= blob fee cap).
    const auto bal_u =
        intx::be::load<intx::uint256>(accounts_.balance_at(sender_idx));
    accounts_.set_balance_at(sender_idx,
        intx::be::store<evmc::uint256be>(bal_u - upfront_u),
        tx_counter_);

    return intrinsic_gas;
}

// EIP-2780 (Amsterdam) authorization charges, per tx (revm
// apply_auth_list_eip2780). `written` holds the accounts whose leaf write
// is already paid for: the sender (in TX_BASE), the recipient of a
// value-bearing call (in TX_VALUE_COST), and each authority once charged
// ACCOUNT_WRITE. `start_delegated` remembers whether an authority was
// delegated when the tx started (before an earlier auth here changed
// it); `bytes_charged`, the authorities already charged for a
// delegation indicator. The lists are tiny, so linear search.
struct ZiskStateDB::AuthCharges {
    TxGas&                                g;
    std::vector<size_t>                   written;
    std::vector<std::pair<size_t, bool>>  start_delegated;
    std::vector<size_t>                   bytes_charged;

    static bool has(const std::vector<size_t>& v, size_t idx) {
        return std::find(v.begin(), v.end(), idx) != v.end();
    }
};

int64_t ZiskStateDB::apply_authorization_list(const Transactions::View& tx,
                                              size_t sender_idx, TxGas& g) noexcept {
    if (tx.type() != Transactions::Type::SetCode) {
        return 0;
    }

    std::optional<AuthCharges> charges;
    if (is_amsterdam_or_later()) {
        charges.emplace(AuthCharges{g, {sender_idx}, {}, {}});
        if (tx.to() != nullptr && intx::be::load<intx::uint256>(tx.value()) != 0) {
            charges->written.push_back(account_row(*tx.to()));
        }
    }

    // Per the EIP, authorizations are applied at the START of the tx
    // (before EVM execution), so the EVM sees the resulting
    // delegations. They also SURVIVE EVM revert, just like the
    // tx-level nonce bump — applied here (before the checkpoint)
    // using raw setters (no journaling). Each auth that fails its
    // validity checks is silently skipped per the EIP. The 25k-per-
    // auth intrinsic-gas cost is included via compute_intrinsic_gas;
    // the 12500 refund per pre-existing delegation accumulates here
    // and folds into the post-EVM refund total.
    const auto auth_outer = rlp::decode_item(tx.authorization_list_rlp());
    if (auth_outer.kind != rlp::ItemKind::List) {
        fatal("EIP-7702: authorization_list is not an RLP list");
    }
    int64_t       auth_refund = 0;
    rlp::ListIter auth_it{auth_outer.payload};
    while (auth_it.has_next()) {
        const auto auth_item = auth_it.next();
        if (auth_item.kind != rlp::ItemKind::List) {
            fatal("EIP-7702: authorization entry not an RLP list");
        }
        auth_refund += process_single_authorization(auth_item, charges ? &*charges : nullptr);
        if (g.runtime_oog) break;  // later authorities aren't touched
    }
    return auth_refund;
}

int64_t ZiskStateDB::process_single_authorization(const rlp::Item& auth_item,
                                                  AuthCharges*     charges) noexcept {
    // Parse the 6 fields per EIP-7702: chain_id, address, nonce,
    // y_parity, r, s.
    rlp::ListIter fit{auth_item.payload};
    if (!fit.has_next()) fatal("EIP-7702: auth missing chain_id");
    // chain_id can be any RLP-scalar-width value (the EIP puts no upper
    // bound on it), but every real chain id fits in kChainId's uint64_t.
    // A canonical (leading-zero-trimmed) RLP integer wider than 8 bytes is
    // therefore guaranteed to be neither 0 nor kChainId — treat it as a
    // (large) mismatch instead of calling as_u64, which fatals the whole
    // block on a >8-byte payload (test_valid_tx_invalid_chain_id's
    // auth_chain_id=2**256-1 case).
    const rlp::Item chain_id_item = fit.next();
    const bool chain_id_oversized = chain_id_item.kind == rlp::ItemKind::String
        && chain_id_item.payload.size() > 8;
    const uint64_t a_chain_id = chain_id_oversized
        ? UINT64_MAX : rlp::as_u64(chain_id_item);
    if (!fit.has_next()) fatal("EIP-7702: auth missing address");
    const auto a_addr_item = fit.next();
    if (a_addr_item.kind != rlp::ItemKind::String ||
        a_addr_item.payload.size() != 20) {
        fatal("EIP-7702: auth address not a 20-byte string");
    }
    evmc::address delegate;
    std::memcpy(delegate.bytes, a_addr_item.payload.data(), 20);
    if (!fit.has_next()) fatal("EIP-7702: auth missing nonce");
    const uint64_t a_nonce = rlp::as_u64(fit.next());
    if (!fit.has_next()) fatal("EIP-7702: auth missing y_parity");
    const uint64_t a_parity = rlp::as_u64(fit.next());
    if (!fit.has_next()) fatal("EIP-7702: auth missing r");
    const auto a_r = rlp::as_u256(fit.next());
    if (!fit.has_next()) fatal("EIP-7702: auth missing s");
    const auto a_s = rlp::as_u256(fit.next());

    // chain_id must be 0 (universal) or match the current chain id;
    // otherwise skip.
    if (a_chain_id != 0 && a_chain_id != kChainId) {
        return 0;
    }
    // EIP-7702 step 2: nonce < 2^64 - 1, checked before the authority
    // is recovered, so a skipped auth doesn't warm it (EEST
    // top_frame_charges_delegation_is_authority, nonce_limit).
    if (a_nonce == UINT64_MAX) {
        return 0;
    }

    // EIP-2 / EIP-7702: s must be in [1, secp256k1n/2]. Out-of-range
    // s values produce a malleable signature that reth (and every
    // conforming EL) rejects. cpp-guest's libsecp256k1 verifier
    // doesn't enforce this — without the check here, an auth with
    // s = N-1 (test_valid_tx_invalid_auth_signature SECP256K1N_1)
    // would be accepted, bumping the signer's nonce + setting code
    // and diverging from reth's empty-diff result.
    //
    // The low-s bound (s in [1, secp256k1n/2]) lives in zeg/zisk_crypto.hpp
    // as is_canonical_low_s (shared with transaction sender recovery). A
    // non-canonical auth is skipped (return 0), not fatal, per EIP-7702.
    if (!is_canonical_low_s(a_s)) {
        return 0;
    }

    // Auth signing hash: keccak256(0x05 || rlp([chain_id, address,
    // nonce])).
    const auto cid_enc   = rlp::encode_u64(a_chain_id);
    const auto addr_enc  = rlp::encode(
        rlp::BytesView{delegate.bytes, 20});
    const auto nonce_enc = rlp::encode_u64(a_nonce);
    const auto list_enc  = rlp::encode_list({
        rlp::BytesView{cid_enc.data(),   cid_enc.size()},
        rlp::BytesView{addr_enc.data(),  addr_enc.size()},
        rlp::BytesView{nonce_enc.data(), nonce_enc.size()},
    });
    std::vector<uint8_t> preimage;
    preimage.reserve(1 + list_enc.size());
    preimage.push_back(0x05);
    preimage.insert(preimage.end(),
                    list_enc.begin(), list_enc.end());
    const auto a_hash = keccak256_bytes32(
        preimage.data(), preimage.size());

    // Recover the auth signer from the signature itself (no prover-supplied
    // pubkey). Per EIP-7702, an auth with an invalid signature — bad parity,
    // out-of-range r, unrecoverable point — is SKIPPED at the block level
    // (the tx still executes; the auth is a no-op).
    if (a_parity > 1) return 0;
    evmc::address signer;
    if (!ecrecover_address(a_hash, a_r, a_s,
                           static_cast<unsigned>(a_parity), signer)) {
        return 0;
    }

    // A well-formed auth signature deterministically recovers `signer`, and
    // the authority is loaded: it must be a row (an empty leaf if it doesn't
    // exist yet).
    const size_t signer_idx = account_row(signer);
    accounts_.bal_access_at(signer_idx);  // EIP-7928: the authority is loaded

    // EIP-2780: note whether the authority was delegated at tx start,
    // the first time this tx's list names it (before any of its auths
    // here is applied).
    if (charges != nullptr &&
        std::none_of(charges->start_delegated.begin(), charges->start_delegated.end(),
                     [&](const auto& e) { return e.first == signer_idx; })) {
        charges->start_delegated.emplace_back(
            signer_idx, accounts_.code_hash_at(signer_idx) != EMPTY_CODE_HASH);
    }

    // EIP-7702: every recovered authority address is added to the
    // tx-level access list (pre-warmed) regardless of whether the
    // auth's other validity checks pass. Do it here, BEFORE the nonce
    // check, so a nonce-mismatched auth still warms its signer.
    accounts_.mark_touched_at(signer_idx, tx_counter_);

    // EIP-7702: per spec, the authority's current code must be
    // either empty (an EOA) or already a delegation designation
    // (a previous 7702 set_code, which is a 23-byte 0xef0100||addr
    // stub). Any other code (test fixtures sometimes plant tiny
    // bytecode like 0x00 STOP at the signer's address) makes the
    // auth invalid and we must NOT bump the nonce or change the
    // code — otherwise reth's BundleState diverges from ours and
    // check_read_only_unchanged fires at end-of-block (see EEST
    // test_account_warming / test_intrinsic_gas_cost /
    // test_gas_cost). Read code_hash first; if non-empty, resolve
    // the actual bytes via Contracts to inspect the prefix.
    const auto signer_code_hash = accounts_.code_hash_at(signer_idx);
    if (signer_code_hash != EMPTY_CODE_HASH) {
        const auto& c = contracts_.by_hash(signer_code_hash);
        const bool is_delegation = c.code_size == 23
            && c.code[0] == 0xef
            && c.code[1] == 0x01
            && c.code[2] == 0x00;
        if (!is_delegation) {
            return 0;
        }
    }

    if (accounts_.nonce_at(signer_idx) != a_nonce) {
        return 0;
    }

    constexpr evmc::address kZeroAddress{};

    // EIP-2780 (Amsterdam): the auth is valid, so charge its
    // state-dependent costs before applying it (revm
    // apply_auth_list_eip2780): a new account for an authority that
    // doesn't exist (EIP-161 non-empty, as account_exists), ACCOUNT_WRITE
    // on the first write to its leaf, and the delegation indicator's
    // bytes when one is newly written. An unaffordable charge stops the
    // runtime phase before this auth is applied.
    if (charges != nullptr) {
        TxGas&           g = charges->g;
        evmone::StateGas state_gas{g.state_gas};
        const bool clearing      = delegate == kZeroAddress;
        const bool delegated_now = accounts_.code_hash_at(signer_idx) != EMPTY_CODE_HASH;
        bool delegated_at_start  = false;
        for (const auto& [idx, d] : charges->start_delegated) {
            if (idx == signer_idx) delegated_at_start = d;
        }
        if (!account_exists(signer) &&
            !state_gas.charge(g.gas, evmone::NEW_ACCOUNT_STATE_GAS)) {
            g.runtime_oog = true;
            return 0;
        }
        if (!AuthCharges::has(charges->written, signer_idx)) {
            constexpr int64_t ACCOUNT_WRITE = 9000;  // EIP-8038
            if (g.gas < ACCOUNT_WRITE) {
                g.runtime_oog = true;
                return 0;
            }
            g.gas -= ACCOUNT_WRITE;
            charges->written.push_back(signer_idx);
        }
        if (!clearing && !delegated_now && !delegated_at_start &&
            !AuthCharges::has(charges->bytes_charged, signer_idx)) {
            constexpr int64_t DELEGATION_BYTES_STATE_GAS = 23 * evmone::COST_PER_STATE_BYTE;
            if (!state_gas.charge(g.gas, DELEGATION_BYTES_STATE_GAS)) {
                g.runtime_oog = true;
                return 0;
            }
            charges->bytes_charged.push_back(signer_idx);
        }
        g.state_gas = state_gas;
    }

    // EIP-7702 refund: PER_EMPTY_ACCOUNT_COST minus
    // PER_AUTH_BASE_COST (25000 − 12500 = 12500) per auth whose
    // signer's account already had state. Read BEFORE the mutation
    // below. "Has state" is the EIP-161 non-empty predicate:
    // nonce != 0 OR balance != 0 OR code != EMPTY — same shape as
    // `account_exists`. Forgetting the balance leg under-refunds
    // for signers that only hold ether (no nonce / no code).
    bool signer_was_non_empty =
        accounts_.nonce_at(signer_idx) != 0 ||
        accounts_.code_hash_at(signer_idx) != EMPTY_CODE_HASH;
    if (!signer_was_non_empty) {
        const auto bal = accounts_.balance_at(signer_idx);
        for (uint8_t b : bal.bytes) {
            if (b != 0) { signer_was_non_empty = true; break; }
        }
    }

    // Bump signer's nonce + set delegation code_hash. These changes
    // survive any EVM revert below (they precede its checkpoint).
    // Amsterdam journals them: a runtime-phase OOG undoes them.
    if (charges != nullptr) {
        journal_.log_nonce(signer_idx, accounts_.nonce_at(signer_idx),
                           accounts_.last_tx_idx_at(signer_idx));
        journal_.log_code_hash(signer_idx, accounts_.code_hash_at(signer_idx),
                               accounts_.last_tx_idx_at(signer_idx));
    }
    accounts_.set_nonce_at(signer_idx, a_nonce + 1, tx_counter_);

    // EIP-7702 carve-out: delegate == 0x000...000 means CLEAR the
    // delegation rather than install a stub. Set code_hash back to
    // EMPTY_CODE_HASH.
    if (delegate == kZeroAddress) {
        accounts_.set_code_hash_at(signer_idx, EMPTY_CODE_HASH, tx_counter_);
    } else {
        uint8_t delegation[23];
        delegation[0] = 0xef;
        delegation[1] = 0x01;
        delegation[2] = 0x00;
        std::memcpy(delegation + 3, delegate.bytes, 20);
        const auto delegation_hash = keccak256_bytes32(
            delegation, sizeof(delegation));
        accounts_.set_code_hash_at(signer_idx, delegation_hash, tx_counter_);
        // EIP-7928: a BAL code change carries the code bytes.
        if (bal_) contracts_.insert(delegation_hash, delegation, sizeof(delegation));
    }

    return (signer_was_non_empty && charges == nullptr) ? 12500 : 0;
}

evmc::Result ZiskStateDB::execute_top_level_frame(const Transactions::View& tx,
                                                  size_t sender_idx,
                                                  TxGas& g) noexcept {
    // A runtime-phase OOG (EIP-2780) includes the tx as an out-of-gas
    // halt: all regular gas consumed, the reservoir returned untouched
    // (the caller undoes the phase's state changes).
    const auto runtime_oog = [&] {
        g.runtime_oog = true;
        return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0,
                            {.left = tx_state_gas_limit_}};
    };
    if (g.runtime_oog) return runtime_oog();

    int64_t          gas = g.gas;
    evmone::StateGas state_gas{g.state_gas};

    // The first frame's charges (EIP-2780 runtime phase, Amsterdam; revm
    // create_init_frame), seen after the authorizations were applied:
    // - a create to an empty target, or a value transfer to an empty
    //   recipient, pays the new account in state gas (EIP-8037), kept
    //   only if the frame succeeds;
    // - a delegated recipient pays for resolving its delegate: WARM_ACCESS,
    //   plus the cold surcharge if the delegate is cold.
    bool new_account_charged = false;
    if (is_amsterdam_or_later()) {
        const bool has_value = intx::be::load<intx::uint256>(tx.value()) != 0;
        if (tx.to() == nullptr || has_value) {
            const evmc::address recipient =
                tx.to() != nullptr
                    ? *tx.to()
                    : compute_create_address(tx.sender(), accounts_.nonce_at(sender_idx) - 1);
            if (!account_exists(recipient)) {
                if (!state_gas.charge(gas, evmone::NEW_ACCOUNT_STATE_GAS)) return runtime_oog();
                new_account_charged = true;
            }
        }
        if (tx.to() != nullptr) {
            evmc::bytes32 code_hash{};
            const auto code = code_and_hash(*tx.to(), code_hash);
            if (code.size() == 23 && code[0] == 0xef && code[1] == 0x01 && code[2] == 0x00) {
                constexpr int64_t WARM_ACCESS     = 100;
                constexpr int64_t COLD_ACCESS_ADD = 3000 - WARM_ACCESS;  // EIP-8038
                if (gas < WARM_ACCESS) return runtime_oog();
                gas -= WARM_ACCESS;
                evmc::address delegate;
                std::memcpy(delegate.bytes, code.data() + 3, 20);
                if (access_account(delegate) == EVMC_ACCESS_COLD) {
                    if (gas < COLD_ACCESS_ADD) {
                        bal_pending_ = kNoBalPending;  // EIP-7928: not loaded
                        return runtime_oog();
                    }
                    gas -= COLD_ACCESS_ADD;
                }
                bal_commit_pending();  // EIP-7928: the delegate is loaded
            }
        }
    }

    auto result = execute_top_level_message(tx, sender_idx, gas, state_gas.left);
    if (result.status_code == EVMC_SUCCESS) {
        result.state_gas.spilled += state_gas.spilled;
    } else {
        // The VM / host already rolled the frame's own state gas back;
        // give back the new-account charge too (a revert keeps the part
        // that returns to regular gas, a halt consumes it). The
        // authorizations' charges stay.
        if (new_account_charged) {
            int64_t refilled = 0;
            state_gas.refill(refilled, evmone::NEW_ACCOUNT_STATE_GAS);
            if (result.status_code == EVMC_REVERT) result.gas_left += refilled;
        }
        result.state_gas = state_gas;
    }
    return result;
}

evmc::Result ZiskStateDB::execute_top_level_message(const Transactions::View& tx,
                                                    size_t  sender_idx,
                                                    int64_t gas,
                                                    int64_t state_gas) noexcept {
    evmc_message msg{};
    msg.sender    = tx.sender();
    msg.value     = tx.value();
    msg.gas       = gas;
    msg.state_gas = state_gas;
    msg.depth     = 0;

    if (tx.to() == nullptr) {
        // ----- Top-level CREATE -----
        //
        // Derive new address using sender's pre-bump nonce (= the
        // current value minus 1, since we just bumped at tx level).
        // Set up the new account (nonce = 1, balance gets the value
        // transfer), then run init code; on success, register the
        // deployed code on the new account.
        const uint64_t sender_nonce_pre =
            accounts_.nonce_at(sender_idx) - 1;
        const evmc::address new_addr =
            compute_create_address(tx.sender(), sender_nonce_pre);

        msg.kind      = EVMC_CREATE;
        msg.recipient = new_addr;
        const auto entry_code = tx.data();

        const size_t new_idx = account_row(new_addr);
        accounts_.bal_access_at(new_idx);  // EIP-7928: loaded for the collision check
        // EIP-2929: newly-created contract is added to the access list
        // as part of looking it up for the collision check below —
        // warmed unconditionally, regardless of whether the create
        // then succeeds or fails, mirroring the nested-CREATE path
        // (call_create). Journaled for consistency, though at top
        // level there's no enclosing checkpoint to roll back to, so
        // the entry is unused either way.
        if (!accounts_.is_warm_at(new_idx, tx_counter_)) {
            journal_.log_account_warm(new_idx,
                                      accounts_.last_tx_idx_at(new_idx));
        }
        accounts_.mark_touched_at(new_idx, tx_counter_);

        // EIP-684 collision (EIP-7610 clarifies storage also counts):
        // if the target already has a nonce, code, or non-zero storage,
        // the CREATE fails with all gas consumed.
        if (accounts_.nonce_at(new_idx) != 0 ||
            accounts_.code_hash_at(new_idx) != EMPTY_CODE_HASH ||
            address_has_storage(new_addr) || has_block_start_storage(new_idx)) {
            return evmc::Result{EVMC_FAILURE, 0, 0, nullptr, 0,
                                {.left = msg.state_gas}};
        }

        // Initialize the new account (nonce = 1) and transfer value.
        // Both go through the journal so a revert unwinds them.
        journal_.log_nonce(new_idx, accounts_.nonce_at(new_idx),
                           accounts_.last_tx_idx_at(new_idx));
        accounts_.set_nonce_at(new_idx, 1, tx_counter_);
        if (intx::be::load<intx::uint256>(msg.value) != 0) {
            transfer_value(msg.sender, new_addr, msg.value);
        }

        // EIP-6780: mark for full-destroy on same-tx SELFDESTRUCT.
        // Success-only — the create has now passed the collision check.
        created_this_tx_idx_.insert(new_idx);

        auto result = evmc::Result{run_frame(&msg, entry_code.data(), entry_code.size(),
            nullptr)};

        if (result.status_code == EVMC_SUCCESS) {
            // EIP-170 (Spurious Dragon): deployed code cannot exceed
            // MAX_CODE_SIZE (24576 B; 65536 B from Amsterdam) — top-level
            // CREATE tx must also enforce this, mirroring the matching
            // check in call_create(). All gas is burned on failure, not
            // just the per-byte deposit refused.
            if (result.output_size > max_code_size()) {
                return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0,
                                    {.left = msg.state_gas}};
            }

            // EIP-3541 (London+): reject deployed code starting with
            // 0xef (valid pre-London). EIP-7702 reinforces this for the delegation prefix
            // 0xef0100 specifically — top-level CREATE tx must also
            // refuse to deploy such code, otherwise the new contract
            // would be indistinguishable from a 7702-installed
            // delegation indicator. Fixture
            // test_deploying_delegation_designation_contract.json
            // exercises this path (a Type-0 creation tx whose init
            // code RETURNs `0xef0100||addr`).
            if (is_london_or_later() && result.output_size > 0 &&
                result.output_data[0] == 0xef) {
                return evmc::Result{EVMC_CONTRACT_VALIDATION_FAILURE,
                                    0, 0, nullptr, 0,
                                    {.left = msg.state_gas}};
            }

            // Code deposit, from the CREATE frame's remaining gas;
            // OOG if insufficient.
            if (!charge_code_deposit(result, is_amsterdam_or_later())) {
                return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0,
                                    {.left = msg.state_gas}};
            }

            const auto deployed_hash = keccak256_bytes32(
                result.output_data, result.output_size);
            // Register the deployed code in the Contracts table so
            // later txs in this block (or later operations in this tx,
            // e.g. when a system call resolves the just-installed
            // EIP-7002/7251 predeploy at end-of-block) can resolve it
            // by hash. The opcode CREATE / CREATE2 path goes through
            // register_deployed_code() which does the same; this
            // top-level CREATE-tx branch was missing the insert.
            // Fixture test_system_contract_deployment exercises this:
            // a Type-0 creation tx deploys the EIP-7002/7251 system
            // contract AT the Prague fork block, and end-of-block
            // collect_withdrawal_requests / collect_consolidation_
            // requests does a system_call into it.
            if (result.output_size > 0) {
                contracts_.insert(deployed_hash, result.output_data,
                                  result.output_size);
            }
            journal_.log_code_hash(new_idx,
                                   accounts_.code_hash_at(new_idx),
                                   accounts_.last_tx_idx_at(new_idx));
            accounts_.set_code_hash_at(new_idx, deployed_hash, tx_counter_);
            // Don't propagate the init code's RETURN payload as the tx's
            // output on success — see the matching fix in call_create().
            return evmc::Result{result.status_code, result.gas_left,
                                result.gas_refund, nullptr, 0, result.state_gas};
        }
        return result;
    }

    // ----- Top-level CALL -----
    msg.kind         = EVMC_CALL;
    msg.recipient    = *tx.to();
    msg.code_address = *tx.to();
    msg.input_data   = tx.data().data();
    msg.input_size   = tx.data().size();

    // Top-level CALL dispatch: if `tx.to` is a precompile address,
    // invoke the precompile directly instead of running its (empty)
    // EVM code through evmone. The nested-CALL path in `call()`
    // already does this, but for a top-level tx whose `to` is e.g.
    // 0x05 (MODEXP), evmone would execute the empty code and return
    // success with full gas — silently bypassing the precompile's
    // gas charge and output. Fixture
    // test_modexp_used_in_transaction_entry_points exercises this:
    // a tx with to=0x05 and ABI-encoded MODEXP calldata expects the
    // EIP-2565 minimum gas (200) plus tx intrinsic; without this
    // dispatch only intrinsic is charged, breaking the post-state.
    //
    // Check BEFORE the EIP-7702 delegation handling: if the call
    // target is a delegated EOA whose delegate happens to be a
    // precompile address, per EIP-7702 the call follows delegation
    // semantics (no-op against the precompile, runs nothing), NOT
    // precompile-dispatch semantics. Fixture
    // test_call_to_precompile_in_pointer_context exercises this.
    if (evmone::state::is_precompile(active_revision(), msg.code_address)) {
        if (bal_) bal_load(msg.code_address);  // EIP-7928: the call loads it
        if (intx::be::load<intx::uint256>(msg.value) != 0) {
            transfer_value(msg.sender, msg.recipient, msg.value);
        }
        return call_precompile_dispatch(msg);
    }

    evmc::bytes32 entry_code_hash{};
    auto entry_code = this->code_and_hash(msg.recipient, entry_code_hash);

    // EIP-7702 top-level delegation: if the recipient is a delegated
    // EOA (code starts with 0xef0100 || delegate), execute the
    // delegate's code instead of the 23-byte stub. evmone follows
    // delegation automatically for CALL/STATICCALL/etc. opcodes
    // inside execution, but NOT for the entry code we hand it for
    // the top-level frame — that's our responsibility.
    if (entry_code.size() >= 23 &&
        entry_code[0] == 0xef && entry_code[1] == 0x01 && entry_code[2] == 0x00) {
        evmc::address delegate;
        std::memcpy(delegate.bytes, entry_code.data() + 3, 20);
        msg.code_address = delegate;
        entry_code = this->code_and_hash(delegate, entry_code_hash);
    }

    if (intx::be::load<intx::uint256>(msg.value) != 0) {
        transfer_value(msg.sender, msg.recipient, msg.value);
    }

    return evmc::Result{run_frame(&msg, entry_code.data(), entry_code.size(),
        analysis_for(entry_code_hash))};
}

ZiskStateDB::TxGasUsed ZiskStateDB::settle_tx_gas(const Transactions::View& tx,
                                                  const evmc::Result&       result,
                                                  size_t                    sender_idx,
                                                  int64_t auth_refund) noexcept {
    // result.gas_left is what remains of `msg.gas` (already net of
    // intrinsic), and result.state_gas.left what remains of the EIP-8037
    // reservoir; both go back to the sender. Total tx gas used is
    // gas_limit − gas_left − state_gas.left. EIP-3529 (London+) halved
    // the refund cap from gas_used/2 to gas_used/5; pre-London forks
    // (Frontier..Berlin) still use the original /2.
    const int64_t gas_left      = result.gas_left + result.state_gas.left;
    const int64_t gas_used_pre  =
        static_cast<int64_t>(tx.gas_limit()) - gas_left;
    const int64_t max_refund    =
        gas_used_pre / (is_london_or_later() ? 5 : 2);
    // EVM-level refund (storage clears, etc.) plus EIP-7702 auth-list
    // refund (12500 per pre-existing signer). Both are subject to the
    // same EIP-3529 cap.
    const int64_t refund_pre_cap = result.gas_refund + auth_refund;
    const int64_t refund         =
        (refund_pre_cap < max_refund) ? refund_pre_cap : max_refund;
    const int64_t gas_remaining_raw = gas_left + refund;
    int64_t gas_used = static_cast<int64_t>(tx.gas_limit()) - gas_remaining_raw;

    // EIP-7623 (Prague): calldata-cost floor. tokens = zero_bytes * 1
    // + non_zero_bytes * 4; floor = 21000 + tokens * 10. The tx must
    // be charged at least the floor — this kicks in for txs with
    // large calldata but low execution (e.g. early-reverting calls).
    // Gated on Prague+: pre-Prague EEST fixtures (Berlin / London /
    // Paris / Shanghai / Cancun) have no floor, and applying it would
    // over-charge low-execution txs (e.g. test_modexp_used_in_
    // transaction_entry_points which calls MODEXP directly with the
    // EIP-2565 minimum 200 gas; the floor would inflate the tx to
    // 25350 gas vs the canonical 22940).
    if (is_prague_or_later()) {
        const int64_t floor_gas = tx_floor_gas_;  // check_transaction
        if (gas_used < floor_gas) {
            gas_used = floor_gas;
        }
    }
    const int64_t gas_remaining =
        static_cast<int64_t>(tx.gas_limit()) - gas_used;

    // The block's share (EIP-8037 / EIP-7778, Amsterdam). State gas used
    // is the reservoir consumed plus the state gas that spilled into
    // regular gas. Neither block dimension is reduced by the refund; the
    // floor applies to the regular one.
    TxGasUsed used{static_cast<uint64_t>(gas_used), static_cast<uint64_t>(gas_used), 0};
    if (is_amsterdam_or_later()) {
        int64_t state_used =
            tx_state_gas_limit_ - result.state_gas.left + result.state_gas.spilled;
        // Spec (gas.py:settle_transaction_gas) clamps state gas used at 0; a
        // negative value would wrap when cast to u64 below (and inflate
        // block_regular). No known path reaches a negative value today.
        state_used = std::max<int64_t>(0, state_used);
        used.block_regular =
            static_cast<uint64_t>(std::max(gas_used_pre - state_used, tx_floor_gas_));
        used.block_state = static_cast<uint64_t>(state_used);
    }

    const auto eff_gas_price_u =
        intx::be::load<intx::uint256>(tx_context_.tx_gas_price);

    // Refund sender: gas_remaining × effective_gas_price.
    {
        const auto credit_u =
            intx::uint256{static_cast<uint64_t>(gas_remaining)} * eff_gas_price_u;
        const auto bal_u =
            intx::be::load<intx::uint256>(accounts_.balance_at(sender_idx));
        accounts_.set_balance_at(sender_idx,
            intx::be::store<evmc::uint256be>(bal_u + credit_u),
            tx_counter_);
    }

    // Pay coinbase the priority-fee portion only (EIP-1559: the
    // base-fee portion is burned). priority_fee = max(0,
    // effective_gas_price − base_fee). The blob-gas portion is burned
    // and never paid to coinbase.
    {
        const auto base_fee_u =
            intx::be::load<intx::uint256>(consensus_.base_fee_per_gas());
        const auto priority_u = (eff_gas_price_u > base_fee_u)
                                    ? (eff_gas_price_u - base_fee_u)
                                    : intx::uint256{0};
        const auto fee_u =
            intx::uint256{static_cast<uint64_t>(gas_used)} * priority_u;
        const size_t coinbase_idx =
            account_row(consensus_.beneficiary());
        const auto bal_u =
            intx::be::load<intx::uint256>(accounts_.balance_at(coinbase_idx));
        accounts_.set_balance_at(coinbase_idx,
            intx::be::store<evmc::uint256be>(bal_u + fee_u),
            tx_counter_);
    }

    return used;
}

void ZiskStateDB::finalize_receipt(const evmc::Result& result,
                                   const TxGasUsed&    used) noexcept {
    // The in-progress receipt was pushed at the start of the
    // iteration and emit_log filled its `logs` (with revert truncation
    // via rollback). Compute the per-tx bloom now from whatever logs
    // survived, then OR into the block bloom, set status + cumGas.
    auto& rcpt = tx_receipts_.back();
    for (const auto& log : rcpt.logs) {
        bloom_add(rcpt.logs_bloom,
                  log.address.bytes, sizeof(log.address.bytes));
        for (const auto& t : log.topics) {
            bloom_add(rcpt.logs_bloom, t.bytes, sizeof(t.bytes));
        }
    }
    bloom_or_into(block_bloom_filter_, rcpt.logs_bloom);
    cumulative_gas_used_     += used.gas_used;
    block_regular_gas_used_  += used.block_regular;
    block_state_gas_used_    += used.block_state;
    rcpt.cumulative_gas_used  = cumulative_gas_used_;
    rcpt.status               = (result.status_code == EVMC_SUCCESS);
}

void ZiskStateDB::post_execute_block() noexcept {
    // EIP-7928: index n+1 covers everything after the last tx.
    if (bal_) bal_->set_index(bal_tx_count_ + 1);
    credit_block_reward();                // pre-Merge PoW reward
    credit_withdrawals();                 // EIP-4895 (Shanghai+)
    // EIP-6110/7002/7251 all activate in Prague. Skip them for pre-
    // Prague blocks (mixed-fork EEST fixtures); their system contracts
    // either don't exist yet or aren't supposed to be queried. For old
    // manifests pre-dating field_count, is_prague_or_later() returns
    // true (field_count=0 → default Pectra), preserving mainnet replay
    // behavior.
    if (is_prague_or_later()) {
        // Order matters: deposit requests must be pushed first so requests_
        // stays in EIP-7685 type-byte order (0x00 → … → 0x04).
        collect_deposit_requests();           // EIP-6110
        collect_withdrawal_requests();        // EIP-7002
        collect_consolidation_requests();     // EIP-7251
        if (is_amsterdam_or_later()) {
            collect_builder_requests();       // EIP-8282
        }
    }
}

void ZiskStateDB::credit_block_reward() noexcept {
    // Pre-Merge protocol-level block reward credited to coinbase at
    // end-of-block. Post-Merge (Paris+) this is zero — there is no
    // PoW subsidy; the only block-level credits are withdrawals
    // (EIP-4895). We detect "post-Merge" via difficulty == 0, which
    // is true for Paris/Shanghai/Cancun/Prague/Osaka (PoS headers
    // pin difficulty to 0).
    //
    // For the forks the EEST corpus exercises (Berlin, London — both
    // post-Constantinople), the reward is a flat 2 ETH. Earlier
    // forks (3 / 5 ETH) aren't represented in our test set, so we
    // don't carry a per-fork table here; if a Frontier/Homestead/etc.
    // fixture surfaces, this needs the proper table.
    //
    // Ommers (uncle rewards) are not credited — EEST fixtures pin
    // sha3Uncles to kEmptyOmmersHash, so the ommer list is empty.
    const auto& diff = consensus_.difficulty();
    bool is_pow = false;
    for (uint8_t b : diff.bytes) {
        if (b != 0) { is_pow = true; break; }
    }
    if (!is_pow) return;

    const auto reward_u = intx::uint256{2} * intx::uint256{1'000'000'000'000'000'000ULL};
    const size_t coinbase_idx = account_row(consensus_.beneficiary());
    const auto bal_u =
        intx::be::load<intx::uint256>(accounts_.balance_at(coinbase_idx));
    accounts_.set_balance_at(coinbase_idx,
        intx::be::store<evmc::uint256be>(bal_u + reward_u),
        tx_counter_);
}

// ----- per-block post-execution phases ---------------------------------------

void ZiskStateDB::credit_withdrawals() noexcept {
    // EIP-4895: credit each withdrawal to its recipient. Withdrawal
    // amounts are in gwei; balances are in wei.
    const auto gwei_to_wei = intx::uint256{1'000'000'000};
    for (const auto& w : consensus_.withdrawals()) {
        const size_t idx = account_row(w.address());
        const auto   bal_u =
            intx::be::load<intx::uint256>(accounts_.balance_at(idx));
        const auto credit_u =
            intx::uint256{w.amount_gwei()} * gwei_to_wei;
        accounts_.set_balance_at(idx,
            intx::be::store<evmc::uint256be>(bal_u + credit_u),
            tx_counter_);
    }
}

void ZiskStateDB::collect_deposit_requests() noexcept {
    // EIP-6110: aggregate every block-level deposit (one 192-byte body
    // per DepositEvent log) into a single type-0x00 entry. Reverted
    // logs are already dropped from tx_receipts_ via the journal/log-
    // checkpoint mechanism.
    std::vector<uint8_t> deposits_buf;
    extract_deposit_requests(tx_receipts_, deposits_buf);
    if (deposits_buf.empty()) {
        return;
    }
    std::vector<uint8_t> req;
    req.reserve(1 + deposits_buf.size());
    req.push_back(kRequestTypeDeposit);
    req.insert(req.end(),
               deposits_buf.begin(), deposits_buf.end());
    requests_.push_back(std::move(req));
}

void ZiskStateDB::collect_withdrawal_requests() noexcept {
    // EIP-7002: calling the predeploy with empty calldata dequeues all
    // pending requests; the canonical contract returns N × 76 bytes
    // (concatenated 76-byte records). Per EIP-7685, requests_hash is
    // computed over the raw predeploy output PREPENDED with the type
    // byte 0x01 — the output is treated as opaque bytes, with no
    // size-alignment constraint at the consensus layer. The 76-byte
    // record shape is a convention of the canonical contract, not a
    // validity rule, so a modified predeploy (EEST
    // test_modified_withdrawal_contract fixtures) that returns a
    // different size is still hashed verbatim and the block stays
    // valid as long as requests_hash matches the header. Validity rules
    // (empty code, failed call) are in collect_system_requests().
    collect_system_requests(
        kWithdrawalRequestsAddress, kRequestTypeWithdrawal,
        "EIP-7002: withdrawal system contract empty (invalid block)",
        "EIP-7002: withdrawal system contract call failed (invalid block)");
}

void ZiskStateDB::collect_consolidation_requests() noexcept {
    // EIP-7251: same shape as EIP-7002 — canonical contract emits N ×
    // 116 bytes (20 + 48 + 48), type byte is 0x02, but consensus only
    // sees opaque bytes. See collect_withdrawal_requests() for the
    // rationale on accepting any size (test_modified_consolidation_
    // contract / test_extra_consolidations).
    collect_system_requests(
        kConsolidationRequestsAddress, kRequestTypeConsolidation,
        "EIP-7251: consolidation system contract empty (invalid block)",
        "EIP-7251: consolidation system contract call failed (invalid block)");
}

void ZiskStateDB::collect_builder_requests() noexcept {
    // EIP-8282 (Amsterdam): the builder deposit (0x03) and builder exit
    // (0x04) predeploys, called in that order after 7002/7251, with the
    // same empty-code and failed-call validity rules.
    collect_system_requests(
        kBuilderDepositRequestsAddress, kRequestTypeBuilderDeposit,
        "EIP-8282: builder deposit system contract empty (invalid block)",
        "EIP-8282: builder deposit system contract call failed (invalid block)");
    collect_system_requests(
        kBuilderExitRequestsAddress, kRequestTypeBuilderExit,
        "EIP-8282: builder exit system contract empty (invalid block)",
        "EIP-8282: builder exit system contract call failed (invalid block)");
}

void ZiskStateDB::collect_system_requests(const evmc::address& addr,
                                          uint8_t              type,
                                          const char*          empty_msg,
                                          const char*          failed_msg) noexcept {
    // Validity: once the fork is active the request predeploy MUST be
    // present. If it has no code at end-of-block the block is invalid
    // (BlockException.SYSTEM_CONTRACT_EMPTY). Calling empty code would
    // otherwise "succeed" as a no-op and silently accept the block. EEST
    // test_system_contract_deployment (deploy_after_fork) exercises this.
    if (get_code_size(addr) == 0) {
        fatal(empty_msg);
    }
    auto result = system_call(addr, {});
    // A failed call (revert, OOG, ...) also makes the block invalid
    // (execution-specs process_checked_system_transaction,
    // BlockException.SYSTEM_CONTRACT_CALL_FAILED).
    if (result.status_code != EVMC_SUCCESS) {
        fatal(failed_msg);
    }
    if (result.output_size == 0) {
        return;
    }
    std::vector<uint8_t> req;
    req.reserve(1 + result.output_size);
    req.push_back(type);
    req.insert(req.end(), result.output_data,
                          result.output_data + result.output_size);
    requests_.push_back(std::move(req));
}

evmc::Result ZiskStateDB::system_call(const evmc::address&     target,
                                      std::span<const uint8_t> calldata) noexcept {
    // Treat every system call as its own EVM frame for the purposes
    // of EIP-2929 warm/cold + EIP-2200 per-tx-original tracking. The
    // bump matters even though system calls don't pay gas: without
    // it, the very first access inside the frame would run with
    // tx_counter_ matching the never-touched sentinel (0), which
    // would make is_warm_at falsely report `true` and mark_touched_at
    // skip its snapshot. Transient storage (EIP-1153) is also reset
    // per-frame.
    ++tx_counter_;
    transient_.reset();

    // A system call runs as SYSTEM_ADDRESS, not as any transaction. Give the
    // frame its own context — origin = SYSTEM_ADDRESS, gas_price = base fee, and
    // no blob hashes (a leftover type-3 blob_hashes pointer from the last tx
    // would otherwise dangle/leak) — while keeping the block-level fields
    // (number/timestamp/coinbase/…). Save and restore the surrounding context so
    // a per-tx context is never clobbered. Defensive today: the predeploys read
    // none of ORIGIN/GASPRICE/BLOBHASH, so none of this changes a valid block.
    const evmc_tx_context saved_ctx = tx_context_;
    evmc_tx_context sys_ctx         = tx_context_;
    sys_ctx.tx_origin         = kSystemAddress;
    sys_ctx.tx_gas_price      = sys_ctx.block_base_fee;
    sys_ctx.blob_hashes       = nullptr;
    sys_ctx.blob_hashes_count = 0;
    set_tx_context(sys_ctx);
    // Clear the per-tx "created this tx" set so a post-block system call does
    // not inherit the last transaction's freshly-created accounts. Only
    // SELFDESTRUCT reads it and the predeploys don't SELFDESTRUCT, so this is
    // defensive.
    created_this_tx_idx_.clear();

    evmc_message msg{};
    msg.kind         = EVMC_CALL;
    msg.sender       = kSystemAddress;
    msg.recipient    = target;
    msg.code_address = target;
    msg.input_data   = calldata.data();
    msg.input_size   = calldata.size();
    msg.gas          = kSystemCallGas;
    // EIP-8037 (Amsterdam): a state-gas reservoir for up to 16 slot
    // allocations, apart from the 30M regular gas (evmone
    // test/state/system_contracts.cpp; EEST test_system_call_execution_*).
    msg.state_gas    = is_amsterdam_or_later() ? 16 * evmone::STORAGE_SET_STATE_GAS : 0;
    msg.value        = evmc::uint256be{};       // 0
    msg.depth        = 0;

    // Standard checkpoint+rollback discipline so a reverted system
    // frame doesn't leave half-written state behind. No gas
    // accounting (system calls have no sender to debit / coinbase to
    // pay); the caller may consume the result's output_data (e.g.
    // for EIP-7002 / EIP-7251 request dequeue).
    const auto cp = checkpoint();
    evmc::bytes32 entry_code_hash{};
    // EIP-7928: the target is loaded even without code (its caller,
    // SYSTEM_ADDRESS, is not).
    const auto entry_code = code_and_hash(target, entry_code_hash);
    in_system_call_ = true;
    auto result = evmc::Result{run_frame(&msg, entry_code.data(), entry_code.size(),
        analysis_for(entry_code_hash))};
    in_system_call_ = false;
    set_tx_context(saved_ctx);  // restore the surrounding block/tx context
    if (result.status_code != EVMC_SUCCESS) {
        rollback(cp);
    }
    return result;
}

} // namespace zeg

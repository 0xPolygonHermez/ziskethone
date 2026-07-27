#include "zeg/zisk_state_db.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

#include <intx/intx.hpp>    // 256-bit add for selfdestruct balance transfer
#include <test/state/precompiles.hpp>  // evmone::state::call_precompile

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
#include "zeg/zisk_crypto.hpp"  // verify_signature_and_get_signer (EIP-7702)

namespace zeg {

namespace {

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
                         Storages&             storages)
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
      ) {}

ZiskStateDB::~ZiskStateDB() {
    // Release every prepared analysis handle (cached on the Contracts, owned by
    // the VM) before destroying the VM.
    contracts_.release_analyses([this](evmc2_pre_execution* pre) {
        vm2_->release_pre_execution(&vm2_->base, pre);
    });
    vm2_->base.destroy(&vm2_->base);
}

// ===== evmc::Host overrides =====
//
// In header declaration order. Most are direct pass-throughs to the
// corresponding Accounts/Storages accessor; the execution-driving ones
// (call, emit_log, access_account, access_storage) do real work.

bool ZiskStateDB::account_exists(const evmc::address& addr) const noexcept {
    // Witness-only model: an address absent from the table is non-existent
    // (the witness reveals every pre-state account along an accessed path;
    // an absent address therefore has empty block-state — a real non-empty
    // account would change the old root and fail the parent anchor, and a
    // prover who hides one only produces a wrong block hash, rejected
    // externally). "Exists" semantically = non-empty (nonzero balance OR
    // nonce OR non-empty code).
    if (!accounts_.contains(addr)) {
        return false;
    }
    const size_t idx = accounts_.index_of(addr);
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
    // A slot absent from the static `Storages` table is a key the witness
    // didn't include — its block-original value is 0 (a non-zero original
    // would be in the account's storage subtree and, if omitted, change the
    // old root and fail the parent anchor). Route it through the per-tx
    // `dynamic_storage_` scratchpad (block-original implicitly 0); surviving
    // non-zero slots are committed to the static table at tx-end so the
    // new-root walk inserts them.
    if (!storages_.contains(addr, key)) {
        auto& ds = const_cast<DynamicStorage&>(dynamic_storage_);
        ds.mark_touched(addr, key, tx_counter_);
        return ds.value(addr, key);
    }
    // `storages_.value(...)` touches the slot for tx_counter_ (snapshots
    // tx_original on first access, marks warm). The const_cast is safe:
    // mods_ is logically mutable scratch — evmc::Host::get_storage is
    // const-by-interface but the per-tx tracking has to happen here.
    return const_cast<Storages&>(storages_).value(addr, key, tx_counter_);
}

evmc_storage_status ZiskStateDB::set_storage(const evmc::address& addr,
                                             const evmc::bytes32& key,
                                             const evmc::bytes32& value) noexcept {
    // See routing comment in get_storage: dynamic_storage_ holds every
    // (addr, key) pair the witness didn't include (block-original 0).
    if (!storages_.contains(addr, key)) {
        // Slot absent from witness: route through dynamic_storage_.
        // access_storage(addr, key) was called by evmone before this,
        // which marked the slot touched and (if absent) inserted it with
        // a zero original. So now we can capture pre-write state and
        // journal it.
        const bool was_present = dynamic_storage_.contains(addr, key);
        const auto current     = dynamic_storage_.value(addr, key);
        const auto original    = dynamic_storage_.tx_original(addr, key, tx_counter_);
        const auto old_tx_idx  = dynamic_storage_.last_tx_idx(addr, key);

        journal_.log_dyn_storage(addr, key, was_present, current, old_tx_idx);
        dynamic_storage_.set_value(addr, key, value, tx_counter_);

        return compute_storage_status(original, current, value);
    }

    // No explicit mark_touched_at here: on Berlin+ revisions evmone
    // always calls access_storage(addr, key) before set_storage, and
    // our access_storage already does the snapshot. So by the time
    // we read tx_original_at below the per-tx-original is in place.
    const size_t idx = storages_.index_of(addr, key);

    const auto& original = storages_.tx_original_at(idx);
    const auto  current  = storages_.value_at(idx);

    journal_.log_storage(idx, current, storages_.last_tx_idx_at(idx));
    storages_.set_value_at(idx, value, tx_counter_);

    return compute_storage_status(original, current, value);
}

evmc::bytes32 ZiskStateDB::get_transient_storage(const evmc::address& addr,
                                                 const evmc::bytes32& key) const noexcept {
    return transient_.get(addr, key);
}

void ZiskStateDB::set_transient_storage(const evmc::address& addr,
                                        const evmc::bytes32& key,
                                        const evmc::bytes32& value) noexcept {
    // Snapshot the slot's pre-write state and journal it BEFORE the
    // mutation so an enclosing revert can restore it. EIP-1153 only
    // requires per-frame reset (handled at tx/system-call boundaries)
    // + per-revert rollback; no warm/cold or "original" semantics.
    const auto prev = transient_.set(addr, key, value);
    journal_.log_transient(addr, key, prev.was_present, prev.value);
}

evmc::uint256be ZiskStateDB::get_balance(const evmc::address& addr) const noexcept {
    // Witness-absent address → non-existent → zero balance (see account_exists).
    if (!accounts_.contains(addr)) {
        return {};
    }
    // const_cast: the per-tx warm-touch mutates accounts_.mods_,
    // which is logically scratch state. Same pattern as get_storage.
    return const_cast<Accounts&>(accounts_).balance(addr, tx_counter_);
}

size_t ZiskStateDB::get_code_size(const evmc::address& addr) const noexcept {
    if (!accounts_.contains(addr)) {
        return 0;  // non-existent account has no code
    }
    const auto hash = const_cast<Accounts&>(accounts_).code_hash(addr, tx_counter_);
    if (hash == EMPTY_CODE_HASH) {
        return 0;
    }
    return static_cast<size_t>(contracts_.by_hash(hash).code_size);
}

evmc::bytes32 ZiskStateDB::get_code_hash(const evmc::address& addr) const noexcept {
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
    //
    // We deliberately do NOT short-circuit on `!accounts_.contains(addr)`
    // here — treating a witness-absent address as "non-existent" would
    // let a malicious prover omit a real contract from the witness and
    // make us return 0, taking the wrong branch for an EXTCODEHASH==0
    // check. `account_exists` (strict: calls index_of which fatals on
    // missing) is the gate that forces the prover to supply the addr.
    if (!account_exists(addr)) {
        return {};
    }
    return const_cast<Accounts&>(accounts_).code_hash(addr, tx_counter_);
}

size_t ZiskStateDB::copy_code(const evmc::address& addr,
                              size_t offset,
                              uint8_t* buffer,
                              size_t buffer_size) const noexcept {
    if (!accounts_.contains(addr)) {
        return 0;  // non-existent account has no code
    }
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
    const size_t src_idx = ensure_account(addr);
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
            // the balance write entirely.
            journal_.log_balance(src_idx, accounts_.balance_at(src_idx),
                                 accounts_.last_tx_idx_at(src_idx));
            accounts_.set_balance_at(src_idx, evmc::uint256be{}, tx_counter_);
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
    const size_t dst_idx = ensure_account(beneficiary);
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
    // gets its full clear (nonce + code_hash + storage + dynamic
    // storage). No journaling needed — the tx has committed and no
    // revert can roll these back.
    for (size_t idx : pending_destruct_) {
        clear_account_for_selfdestruct(idx);
    }
    pending_destruct_.clear();
}

void ZiskStateDB::commit_dynamic_storage() noexcept {
    // Move surviving fresh-account slots into the static `Storages` table so
    // the post-block new-root walk can insert them. The block-original of a
    // dynamic slot is 0 (it didn't exist pre-block); only non-zero current
    // values matter (a zero slot has no trie effect). Appended rows are
    // "created" (index >= the witness storage count) and get inserted into
    // their owning account's storage subtree by calculate_new_state_root.
    // No journaling: the tx has committed and no revert crosses the boundary.
    for (const auto& [addr, inner] : dynamic_storage_.entries()) {
        // Skip slots whose owning account ended empty / absent: an empty
        // account (nonce=0, balance=0, code=EMPTY) is removed by EIP-161
        // along with its storage, so its slots must not enter the trie. An
        // account never added to the table is empty by definition.
        if (!accounts_.contains(addr)) {
            continue;
        }
        const size_t a_idx = accounts_.index_of(addr);
        if (is_empty_account(accounts_.nonce_at(a_idx),
                             accounts_.balance_at(a_idx),
                             accounts_.code_hash_at(a_idx))) {
            continue;
        }
        for (const auto& [pos, slot] : inner) {
            if (slot.value == evmc::bytes32{}) {
                continue;
            }
            if (storages_.contains(addr, pos)) {
                storages_.set_value(addr, pos, slot.value, tx_counter_);
            } else {
                const size_t idx = storages_.append(addr, pos, evmc::bytes32{});
                storages_.set_value_at(idx, slot.value, tx_counter_);
            }
        }
    }
    dynamic_storage_.clear();
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
    journal_.log_balance(src_idx, accounts_.balance_at(src_idx),
                         accounts_.last_tx_idx_at(src_idx));
    accounts_.set_balance_at(src_idx, evmc::uint256be{}, tx_counter_);

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
        journal_.log_storage(i, cur, storages_.last_tx_idx_at(i));
        storages_.set_value_at(i, evmc::bytes32{}, tx_counter_);
    }

    // Dynamic-storage side: drop every slot the EVM SSTORE'd on this
    // freshly-created address in O(1) (the nested unordered_map's
    // erase is constant-time on the outer key). The journal records
    // the entire snapshot so a frame revert restores it atomically.
    if (dynamic_storage_.contains(addr)) {
        auto snap = dynamic_storage_.erase_account(addr);
        journal_.log_dyn_account_erase(addr, std::move(snap));
    }
}

evmc::Result ZiskStateDB::call(const evmc_message& msg) noexcept {
    // Precompile dispatch. Mirror the test/state host check: only a
    // straight CALL (not a DELEGATECALL into the precompile address)
    // hits the precompile dispatcher — DELEGATECALL into a precompile
    // address runs the caller's code with the precompile's "code"
    // (which is empty), per EVM semantics.
    if ((msg.flags & EVMC_DELEGATED) == 0 &&
        evmone::state::is_precompile(active_revision(), msg.code_address)) {
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
        case EVMC_EOFCREATE:
            return call_create(msg, cp);
    }

    auto result = evmc::Result{vm2_->execute2(
        &vm2_->base, &evmc::Host::get_interface(), to_context(),
        active_revision(), &msg, code.data(), code.size(),
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
        return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0};
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
        return evmc::Result{EVMC_SUCCESS, gas_left, 0, nullptr, 0};  // empty output
    const unsigned recid = static_cast<unsigned>(in[63] - 27);

    evmc::bytes32   hash;  std::memcpy(hash.bytes, in,      32);
    evmc::uint256be r;     std::memcpy(r.bytes,    in + 64, 32);
    evmc::uint256be s;     std::memcpy(s.bytes,    in + 96, 32);

    evmc::address signer{};
    if (!ecrecover_address(hash, r, s, recid, signer))
        return evmc::Result{EVMC_SUCCESS, gas_left, 0, nullptr, 0};  // not recoverable

    // Output: 20-byte address, left-padded to 32 bytes. evmc::Result copies it.
    uint8_t out[32] = {};
    std::memcpy(out + 12, signer.bytes, 20);
    return evmc::Result{EVMC_SUCCESS, gas_left, 0, out, sizeof(out)};
}

evmc_tx_context ZiskStateDB::get_tx_context() const noexcept {
    return tx_context_;
}

evmc::bytes32 ZiskStateDB::get_block_hash(int64_t block_number) const noexcept {
    const int64_t current = static_cast<int64_t>(consensus_.number());
    const int64_t diff    = current - block_number;
    // EVM BLOCKHASH semantics: zero outside [1, 256] (the opcode's own
    // depth limit; EIP-2935 history extends this via the system
    // contract, not via the opcode).
    if (diff < 1 || diff > 256) {
        return {};
    }
    // The ancestor set is SPARSE (only the blocks the witness referenced), so
    // resolve by block number, not positionally. A missing ancestor yields
    // zero — correct, since the witness ships every depth the block asks for.
    //
    // NB: consensus.parent_hash() is the parent's STATE_ROOT in this guest's
    // binary format (the pre-execution root anchor), NOT the parent's block
    // hash — never use it for BLOCKHASH.
    const uint64_t target = static_cast<uint64_t>(block_number);
    if (const evmc::bytes32* h = previous_blocks_.hash_of_number(target)) {
        return *h;
    }
    return {};
}

void ZiskStateDB::emit_log(const evmc::address& addr,
                           const uint8_t* data,
                           size_t data_size,
                           const evmc::bytes32 topics[],
                           size_t topics_count) noexcept {
    // The current tx's receipt was pushed onto tx_receipts_ at the
    // start of the iteration in process_transactions; we just append
    // the log here. Owned copies so the EVM is free to release its
    // buffers after this returns.
    LogEntry entry;
    entry.address = addr;
    entry.topics.assign(topics, topics + topics_count);
    entry.data.assign  (data,   data   + data_size);
    tx_receipts_.back().logs.push_back(std::move(entry));
}

evmc_access_status ZiskStateDB::access_account(const evmc::address& addr) noexcept {
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
        return EVMC_ACCESS_WARM;
    }
    // A witness-absent address is non-existent (empty) — but we still must
    // track its EIP-2929 warm/cold state across accesses within the tx
    // (e.g. a delegate target read twice: cold then warm). `ensure_account`
    // gives it an empty table row so the normal warm machinery (below)
    // applies; the empty row is skipped by the new-root walk, so it doesn't
    // enter the trie.
    const size_t idx      = ensure_account(addr);
    const bool   was_warm = accounts_.is_warm_at(idx, tx_counter_);
    if (!was_warm) {
        // Journal the cold→warm transition so a reverted EVM frame
        // restores cold-ness (EIP-2929 / EIP-2200 gas accounting).
        journal_.log_account_warm(idx, accounts_.last_tx_idx_at(idx));
    }
    accounts_.mark_touched_at(idx, tx_counter_);
    return was_warm ? EVMC_ACCESS_WARM : EVMC_ACCESS_COLD;
}

evmc_access_status ZiskStateDB::access_storage(const evmc::address& addr,
                                               const evmc::bytes32& key) noexcept {
    // Same routing rule as get_storage/set_storage: any slot the witness
    // didn't include goes through dynamic_storage_ (block-original 0).
    if (!storages_.contains(addr, key)) {
        // Witness-absent slot: route through dynamic_storage_. We
        // auto-insert the slot if absent
        // (mark_touched does it) so the subsequent SLOAD/SSTORE find
        // an entry to read/journal. For the journal: log the cold→warm
        // transition so a revert restores the slot's prior state
        // (which may be "absent" if this access is what created the
        // entry).
        const bool was_present = dynamic_storage_.contains(addr, key);
        const bool was_warm = was_present
            && dynamic_storage_.is_warm(addr, key, tx_counter_);
        if (!was_warm) {
            const uint64_t old_tx_idx = was_present
                ? dynamic_storage_.last_tx_idx(addr, key)
                : 0;
            if (was_present) {
                journal_.log_dyn_storage_warm(addr, key, old_tx_idx);
            } else {
                // Insertion-via-access: journal as a "was_present=false"
                // dyn_storage entry so rollback removes the slot.
                journal_.log_dyn_storage(addr, key, /*was_present=*/false,
                                         evmc::bytes32{}, 0);
            }
        }
        dynamic_storage_.mark_touched(addr, key, tx_counter_);
        return was_warm ? EVMC_ACCESS_WARM : EVMC_ACCESS_COLD;
    }

    // EIP-2929 warm/cold: a slot is warm iff it was already touched in
    // this tx (last_tx_idx == tx_counter_). Either way, touch it now
    // so the next access sees it warm.
    const size_t idx       = storages_.index_of(addr, key);
    const bool   was_warm  = storages_.is_warm_at(idx, tx_counter_);
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
    if (!accounts_.contains(addr)) {
        return {};  // non-existent account has no code
    }
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
    if (c.analysis == nullptr) {  // prepare once per distinct bytecode per block
        c.analysis = vm2_->prepare(&vm2_->base, c.code,
                                   static_cast<size_t>(c.code_size));
    }
    return c.analysis;
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
    journal_.rollback(cp.journal_cp, accounts_, storages_, dynamic_storage_, transient_, pending_destruct_);
    if (!tx_receipts_.empty()) {
        tx_receipts_.back().logs.resize(cp.log_count);
    }
}

void ZiskStateDB::execute_block(const Transactions& transactions) noexcept {
    pre_execute_block ();
    process_transactions(transactions);
    post_execute_block();

    // Commit every surviving fresh-account slot (block-original 0) from the
    // dynamic scratchpad into the static `Storages` table so the new-root
    // walk inserts them. Done ONCE at block-end — captures the pre-block
    // (EIP-2935/4788) and post-block (EIP-7002/7251) system-call writes,
    // which run outside the tx loop. Same-tx-SELFDESTRUCT'd slots were
    // already dropped by erase_account, so they aren't committed.
    commit_dynamic_storage();

    // Receipts trie root: built from the finalized tx_receipts_, one
    // leaf per tx keyed by RLP(tx_index).
    {
        MerklePatriciaTrie trie;
        for (size_t i = 0; i < tx_receipts_.size(); ++i) {
            trie.insert(rlp::encode_u64(i), encode_receipt(tx_receipts_[i]));
        }
        receipts_root_ = trie.root_hash();
    }

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

size_t ZiskStateDB::ensure_account(const evmc::address& addr) noexcept {
    if (accounts_.contains(addr)) {
        return accounts_.index_of(addr);
    }
    // No witness row — this address is being created or credited this block
    // (CREATE target, value-transfer recipient, withdrawal/coinbase). Append
    // an empty (non-existent) row into the table's slack. Its block-original
    // is empty, so the new-root walk inserts it only if it ends non-empty.
    // No journal entry is needed for the append itself: a frame revert
    // restores the fields to empty via their own journal logs, rendering the
    // row non-existent again (the now-empty row is harmless).
    //
    // EXCEPTION: a non-empty, preimage-less account (a CREATE2 target funded
    // in a prior block, or simply a real contract the tracer never touched)
    // exists only as an Op::PhantomLeaf — its fields are in the trie, not
    // this table. StateRoot recorded keccak(addr) -> {nonce, balance,
    // code_hash}; if this address matches, seed the row's ORIGINAL from it
    // so any touch here (a CREATE preserving pre-existing funds, or merely an
    // EIP-2929 access-warm probe that never mutates the account) reflects the
    // REAL pre-state fields instead of silently reverting to an empty
    // account. Seeding the ORIGINAL (not just current) is load-bearing: the
    // new-root pass supersedes the phantom leaf only when original != empty,
    // which requires the original to reflect the true pre-state fields —
    // and a probe that never mutates the row leaves current == original, so
    // the resurrected leaf rebuilds to the exact same RLP/hash as the
    // phantom it replaces.
    const evmc::bytes32 addr_hash = keccak256_bytes32(addr.bytes, sizeof(addr.bytes));
    if (const Accounts::PhantomAccount* ph = accounts_.phantom_account(addr_hash)) {
        return accounts_.append(addr, ph->nonce, ph->balance, ph->code_hash);
    }
    return accounts_.append(addr, 0, evmc::uint256be{}, EMPTY_CODE_HASH);
}

void ZiskStateDB::transfer_value(const evmc::address& from,
                                 const evmc::address& to,
                                 const evmc::uint256be& value) noexcept {
    const size_t from_idx = ensure_account(from);
    const size_t to_idx   = ensure_account(to);

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
    const size_t   sender_idx       = ensure_account(msg.sender);
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
        return evmc::Result{EVMC_SUCCESS, msg.gas, 0, nullptr, 0};
    }

    const auto new_addr =
        derive_create_address(msg, sender_nonce_pre, init_code, init_size);

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
    const size_t na_idx = ensure_account(new_addr);
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
        return evmc::Result{EVMC_FAILURE, 0, 0, nullptr, 0};
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
    auto result = evmc::Result{vm2_->execute2(
        &vm2_->base, &evmc::Host::get_interface(), to_context(),
        active_revision(), &create_msg, init_code, init_size, nullptr)};
    if (result.status_code != EVMC_SUCCESS) {
        rollback(cp_after_bump);
        return result;
    }

    // EIP-170 (Spurious Dragon): deployed code cannot exceed
    // MAX_CODE_SIZE (24576 B). Checked BEFORE EIP-3541 below, matching
    // reth/geth's ordering. Every fork this guest targets (Berlin+)
    // postdates Spurious Dragon, so no fork gate is needed. On failure
    // all gas allocated to this CREATE is burned (gas_left=0) rather
    // than only refusing the per-byte deposit cost — the create-vs-OOG
    // gap this closes: codesizeOOGInvalidSize, createCodeSizeLimit,
    // create2CodeSizeLimit, CreateAddressWarmAfterFail's *_code_too_big
    // cases, createLargeResult's *_RETURN_HUGE/TOOBIG cases, and
    // CREATE_ContractRETURNBigOffset.
    constexpr size_t kMaxCodeSize = 24576;
    if (result.output_size > kMaxCodeSize) {
        rollback(cp_after_bump);
        return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0};
    }

    // EIP-3541 (London): contracts cannot have deployed code that
    // starts with the 0xef byte. EIP-7702 extends this for the
    // delegation-designation prefix 0xef0100 specifically — CREATE/
    // CREATE2 must reject init code that RETURNS code starting with
    // these bytes (otherwise the deployed contract would be
    // indistinguishable from a 7702-installed delegation indicator).
    // Reth rejects such CREATEs; fixtures
    // test_creating_delegation_designation_contract and
    // test_deploying_delegation_designation_contract verify this.
    if (result.output_size > 0 && result.output_data[0] == 0xef) {
        rollback(cp_after_bump);
        return evmc::Result{EVMC_CONTRACT_VALIDATION_FAILURE, 0, 0, nullptr, 0};
    }

    // EIP-2 code-deposit cost (200 gas per byte of deployed code).
    // Charged AFTER the init code's RETURN, deducted from result's
    // remaining gas. If the leftover gas can't cover the deposit, the
    // whole CREATE fails (per EIP-2 / Homestead+ semantics).
    constexpr int64_t CODE_DEPOSIT_COST = 200;
    const int64_t deposit =
        static_cast<int64_t>(result.output_size) * CODE_DEPOSIT_COST;
    if (result.gas_left < deposit) {
        rollback(cp_after_bump);
        return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0};
    }
    result.gas_left -= deposit;

    // 5. Register the deployed code on the new account. A *successful*
    //    CREATE/CREATE2 must not propagate the init code's RETURN payload
    //    as call return-data (only a REVERT's payload does) — build a
    //    fresh Result with empty output so RETURNDATASIZE reads 0 to the
    //    caller afterward, matching evmone's own reference Host::create()
    //    (test/state/host.cpp), which does the same on its success path.
    register_deployed_code(new_addr, result);
    return evmc::Result{result.status_code, result.gas_left, result.gas_refund,
                        new_addr};
}

evmc::address ZiskStateDB::derive_create_address(
        const evmc_message& msg,
        uint64_t            sender_nonce_pre,
        const uint8_t*      init_code,
        std::size_t         init_size) noexcept {
    if (msg.kind == EVMC_CREATE) {
        return compute_create_address(msg.sender, sender_nonce_pre);
    }
    // EVMC_CREATE2 / EVMC_EOFCREATE — same formula, distinguished only
    // by what bytes the EVM hands us as the init code.
    return compute_create2_address(msg.sender, msg.create2_salt,
                                   init_code, init_size);
}

bool ZiskStateDB::address_has_storage(const evmc::address& addr) const noexcept {
    for (size_t i : storages_.slots_of(addr)) {
        if (!is_zero_value(storages_.value_at(i))) return true;
    }
    const auto& outer = dynamic_storage_.entries();
    const auto  it     = outer.find(addr);
    if (it != outer.end()) {
        for (const auto& [pos, slot] : it->second) {
            if (!is_zero_value(slot.value)) return true;
        }
    }
    return false;
}

bool ZiskStateDB::init_create_account(const evmc::address& new_addr,
                                      const evmc_message&  msg) noexcept {
    // EIP-684 collision check (EIP-7610 clarifies storage also counts).
    // The address may have no witness row (a brand-new contract address)
    // — `ensure_account` appends an empty row for it. It must look empty
    // (nonce == 0, code_hash == EMPTY, and no non-zero storage slots).
    const size_t new_idx = ensure_account(new_addr);
    if (accounts_.nonce_at(new_idx) != 0 ||
        accounts_.code_hash_at(new_idx) != EMPTY_CODE_HASH ||
        address_has_storage(new_addr)) {
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
        transient_.reset();
        created_this_tx_idx_.clear();
        delegated_this_tx_idx_.clear();
        // pending_destruct_ is also per-tx — `apply_pending_destructs`
        // at the END of the previous iteration drained it, so this
        // clear is just a paranoia guard (also handles tx 0).
        pending_destruct_.clear();
        // `dynamic_storage_` is empty at the start of each tx: the prior
        // tx's surviving fresh-account slots were committed to the static
        // `Storages` table by `commit_dynamic_storage` at its end (and any
        // same-tx-SELFDESTRUCT slots were dropped by `erase_account`).

        const auto& tx = transactions.at(i);

        // EIP-2929 / EIP-3651 / EIP-2930 / EIP-7702 pre-warming.
        // Marking these warm BEFORE the EVM starts means the first
        // access by the EVM charges WARM cost (100) instead of
        // COLD (2600 for accounts, 2100 for slots).
        pre_warm_for_tx(tx);

        // Push the receipt for this tx up front. emit_log appends to
        // tx_receipts_.back().logs during execution; finalize_receipt
        // fills status / bloom / cumGas at the end of the iteration.
        tx_receipts_.emplace_back().tx_type = tx.type();

        // Backing storage for the blob-hashes and initcodes arrays
        // pointed to by the per-tx tx_context. Must outlive the execute2
        // call below — the ctx fields are raw pointers into these vectors.
        std::vector<evmc::bytes32>    blob_hashes;
        std::vector<evmc_tx_initcode> initcodes_vec;
        set_tx_context(build_per_tx_context(tx, blob_hashes, initcodes_vec));

        // Pre-EVM accounting (NOT journaled — survives EVM revert).
        const size_t  sender_idx    = ensure_account(tx.sender());
        const int64_t intrinsic_gas = apply_pre_evm_accounting(tx, sender_idx);

        // EIP-7702 authorization list (Type-4 only). Returns the
        // 12500-per-pre-existing-signer refund that folds into the
        // post-EVM refund cap.
        const int64_t auth_refund = apply_authorization_list(tx);

        // Checkpoint AFTER the upfront accounting + EIP-7702 auths so
        // none of those are rolled back on EVM revert. State changes
        // made inside the checkpoint (value transfer, EVM writes) are
        // undone if the frame fails.
        const auto cp     = checkpoint();
        std::fprintf(stderr, "TX %zu START\n", i);
        auto       result = execute_top_level_frame(tx, sender_idx, intrinsic_gas);
        if (result.status_code != EVMC_SUCCESS) {
            rollback(cp);
        }

        const uint64_t gas_used = settle_tx_gas(tx, result, sender_idx, auth_refund);
        std::fprintf(stderr, "TX %zu gas_used=%llu status=%d\n",
                     i, (unsigned long long)gas_used,
                     (int)result.status_code);
        finalize_receipt(result, gas_used);

        // Apply deferred SELFDESTRUCT clears now that the tx has
        // committed. Per Yellow Paper, destruction happens at the
        // end of the TRANSACTION, not at the SELFDESTRUCT opcode.
        // See pending_destruct_ in the header for the rationale.
        apply_pending_destructs();
    }
}

// ----- per-tx pipeline helpers ----------------------------------------------

void ZiskStateDB::pre_warm_for_tx(const Transactions::View& tx) noexcept {
    auto warm_addr = [&](const evmc::address& a) {
        // Precompiles are inherently warm — no Accounts entry needed.
        if (evmone::state::is_precompile(active_revision(), a)) {
            return;
        }
        // EIP-2930 lets a tx pre-declare addrs it might touch. A
        // witness-absent address is empty; `ensure_account` gives it a row
        // so its warmth can be tracked (matching the static branch), so the
        // first real access is WARM. The empty row is skipped by the
        // new-root walk.
        const size_t idx = ensure_account(a);
        accounts_.mark_touched_at(idx, tx_counter_);
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
                if (!storages_.contains(a, slot)) {
                    // Witness-absent access-list slot (block-original 0):
                    // pre-warm it in the dynamic table so its first SLOAD/
                    // SSTORE is WARM (EIP-2930). Mirrors the static branch
                    // (not journaled — access-list warming is tx-initial).
                    dynamic_storage_.mark_touched(a, slot, tx_counter_);
                    continue;
                }
                const size_t sidx = storages_.index_of(a, slot);
                storages_.mark_touched_at(sidx, tx_counter_);
            }
        }
    }

    // EIP-7702 authority addresses are pre-warmed during
    // apply_authorization_list (which is called right after this
    // helper but before EVM execution — also OK).
}

evmc_tx_context ZiskStateDB::build_per_tx_context(
        const Transactions::View&      tx,
        std::vector<evmc::bytes32>&    blob_hashes,
        std::vector<evmc_tx_initcode>& initcodes_vec) noexcept {
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

    // EIP-7873 initcodes — Type 5 (Osaka) only. Each entry's `code`
    // points zero-copy into the envelope; `hash` is keccak256 of those
    // bytes (the TXCREATE lookup key).
    ctx.initcodes       = nullptr;
    ctx.initcodes_count = 0;
    if (tx.type() == TxType::Osaka) {
        const auto raw   = tx.initcodes_rlp();
        const auto outer = rlp::decode_item(raw);
        if (outer.kind != rlp::ItemKind::List) {
            fatal("Osaka tx: initcodes is not an RLP list");
        }
        rlp::ListIter it{outer.payload};
        while (it.has_next()) {
            const auto item = it.next();
            if (item.kind != rlp::ItemKind::String) {
                fatal("Osaka tx: initcodes entry is not an RLP string");
            }
            evmc_tx_initcode entry{};
            entry.code      = item.payload.data();
            entry.code_size = item.payload.size();
            entry.hash      = keccak256_bytes32(entry.code, entry.code_size);
            initcodes_vec.push_back(entry);
        }
        ctx.initcodes       = initcodes_vec.data();
        ctx.initcodes_count = initcodes_vec.size();
    }

    return ctx;
}

int64_t ZiskStateDB::apply_pre_evm_accounting(const Transactions::View& tx,
                                              size_t sender_idx) noexcept {
    using TxType = Transactions::Type;

    // EIP-161 / YP §6: sender nonce += 1, then debit upfront gas
    // (gas_limit × eff_gas_price + blob_gas × blob_base_fee). The
    // blob portion is burned. These changes are kept even if the EVM
    // frame reverts, matching mainnet semantics.
    const int64_t intrinsic_gas = compute_intrinsic_gas(tx, is_shanghai_or_later());
    if (static_cast<int64_t>(tx.gas_limit()) < intrinsic_gas) {
        fatal("tx gas_limit below intrinsic gas");
    }

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

    const auto bal_u =
        intx::be::load<intx::uint256>(accounts_.balance_at(sender_idx));
    // Tx validity: sender must be able to cover the entire upfront
    // cost (execution gas + blob fee + value would also count if not
    // transferred separately by the EVM frame — here just upfront gas
    // + blob, since value transfer is journaled inside the checkpoint
    // taken by the caller).
    if (bal_u < upfront_u) {
        fatal("tx sender balance below upfront cost");
    }
    accounts_.set_balance_at(sender_idx,
        intx::be::store<evmc::uint256be>(bal_u - upfront_u),
        tx_counter_);

    return intrinsic_gas;
}

int64_t ZiskStateDB::apply_authorization_list(const Transactions::View& tx) noexcept {
    if (tx.type() != Transactions::Type::SetCode) {
        return 0;
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
        auth_refund += process_single_authorization(auth_item);
    }
    return auth_refund;
}

int64_t ZiskStateDB::process_single_authorization(const rlp::Item& auth_item) noexcept {
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

    // EIP-2 / EIP-7702: s must be in [1, secp256k1n/2]. Out-of-range
    // s values produce a malleable signature that reth (and every
    // conforming EL) rejects. cpp-guest's libsecp256k1 verifier
    // doesn't enforce this — without the check here, an auth with
    // s = N-1 (test_valid_tx_invalid_auth_signature SECP256K1N_1)
    // would be accepted, bumping the signer's nonce + setting code
    // and diverging from reth's empty-diff result.
    //
    // secp256k1_N/2 = floor(N/2)
    //   = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    static constexpr uint8_t kSecp256k1NHalf[32] = {
        0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,
        0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0,
    };
    {
        // Lexicographic big-endian compare: a_s > N/2 -> skip.
        int cmp = std::memcmp(a_s.bytes, kSecp256k1NHalf, 32);
        if (cmp > 0) return 0;
        // s == 0 is also invalid (no signature).
        bool s_is_zero = true;
        for (uint8_t b : a_s.bytes) {
            if (b != 0) { s_is_zero = false; break; }
        }
        if (s_is_zero) return 0;
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

    // A well-formed auth signature deterministically recovers `signer`. If
    // the witness didn't reveal it, it's a fresh authority with empty
    // block-state — `ensure_account` appends an empty row and the new-root
    // pass inserts it (fataling if its trie path is an unrevealed Hash, so a
    // prover can't hide a real account behind Op::Hash to drop the auth).
    const size_t signer_idx = ensure_account(signer);

    // EIP-7702: refuse to bump if signer's nonce is already at the
    // u64 ceiling — the bump would overflow. reth applies this guard
    // (test_nonce_overflow_after_first_authorization's second auth
    // sees signer.nonce == UINT64_MAX from the prior auth and
    // rejects). cpp-guest's wrap-around would silently set nonce=0
    // and diverge.
    if (accounts_.nonce_at(signer_idx) == UINT64_MAX) {
        return 0;
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

    // Bump signer's nonce + set delegation code_hash. Raw setters —
    // these changes survive any EVM revert below.
    accounts_.set_nonce_at(signer_idx, a_nonce + 1, tx_counter_);

    // EIP-7702 carve-out: delegate == 0x000...000 means CLEAR the
    // delegation rather than install a stub. Set code_hash back to
    // EMPTY_CODE_HASH.
    constexpr evmc::address kZeroAddress{};
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
        // Track this EOA as a dynamic-storage routing target for the
        // rest of the tx — see the comment on `delegated_this_tx_idx_`
        // for the security argument. We only do this on the
        // delegation-SET branch; the clear branch above leaves the
        // EOA code-less again, so it doesn't need the routing.
        delegated_this_tx_idx_.insert(signer_idx);
    }

    return signer_was_non_empty ? 12500 : 0;
}

evmc::Result ZiskStateDB::execute_top_level_frame(const Transactions::View& tx,
                                                  size_t sender_idx,
                                                  int64_t intrinsic_gas) noexcept {
    evmc_message msg{};
    msg.sender = tx.sender();
    msg.value  = tx.value();
    msg.gas    = static_cast<int64_t>(tx.gas_limit()) - intrinsic_gas;
    msg.depth  = 0;

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

        const size_t new_idx = ensure_account(new_addr);
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
            address_has_storage(new_addr)) {
            return evmc::Result{EVMC_FAILURE, 0, 0, nullptr, 0};
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

        auto result = evmc::Result{vm2_->execute2(
            &vm2_->base, &evmc::Host::get_interface(), to_context(),
            active_revision(), &msg, entry_code.data(), entry_code.size(),
            nullptr)};

        if (result.status_code == EVMC_SUCCESS) {
            // EIP-170 (Spurious Dragon): deployed code cannot exceed
            // MAX_CODE_SIZE (24576 B) — top-level CREATE tx must also
            // enforce this, mirroring the matching check in
            // call_create(). All gas is burned on failure, not just
            // the per-byte deposit refused.
            constexpr size_t kMaxCodeSize = 24576;
            if (result.output_size > kMaxCodeSize) {
                return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0};
            }

            // EIP-3541 (London): reject deployed code starting with
            // 0xef. EIP-7702 reinforces this for the delegation prefix
            // 0xef0100 specifically — top-level CREATE tx must also
            // refuse to deploy such code, otherwise the new contract
            // would be indistinguishable from a 7702-installed
            // delegation indicator. Fixture
            // test_deploying_delegation_designation_contract.json
            // exercises this path (a Type-0 creation tx whose init
            // code RETURNs `0xef0100||addr`).
            if (result.output_size > 0 && result.output_data[0] == 0xef) {
                return evmc::Result{EVMC_CONTRACT_VALIDATION_FAILURE,
                                    0, 0, nullptr, 0};
            }

            // EIP-2 code deposit cost (200 / byte). Deducted from
            // the CREATE frame's remaining gas; OOG if insufficient.
            constexpr int64_t CODE_DEPOSIT_COST = 200;
            const int64_t deposit =
                static_cast<int64_t>(result.output_size) * CODE_DEPOSIT_COST;
            if (result.gas_left < deposit) {
                return evmc::Result{EVMC_OUT_OF_GAS, 0, 0, nullptr, 0};
            }
            result.gas_left -= deposit;

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
                                result.gas_refund, new_addr};
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

    return evmc::Result{vm2_->execute2(
        &vm2_->base, &evmc::Host::get_interface(), to_context(),
        active_revision(), &msg, entry_code.data(), entry_code.size(),
        analysis_for(entry_code_hash))};
}

uint64_t ZiskStateDB::settle_tx_gas(const Transactions::View& tx,
                                    const evmc::Result&       result,
                                    size_t                    sender_idx,
                                    int64_t                   auth_refund) noexcept {
    // result.gas_left is what remains of `msg.gas` (already net of
    // intrinsic). Total tx gas used is gas_limit − gas_left. EIP-3529
    // (London+) halved the refund cap from gas_used/2 to gas_used/5;
    // pre-London forks (Frontier..Berlin) still use the original /2.
    const int64_t gas_left      = result.gas_left;
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
        const auto data = tx.data();
        const int64_t tokens = static_cast<int64_t>(data.size()) +
                               static_cast<int64_t>(count_nonzero_bytes(data)) * 3;
        const int64_t floor_gas = 21000 + tokens * 10;
        if (gas_used < floor_gas) {
            gas_used = floor_gas;
        }
    }
    const int64_t gas_remaining =
        static_cast<int64_t>(tx.gas_limit()) - gas_used;

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
            ensure_account(consensus_.beneficiary());
        const auto bal_u =
            intx::be::load<intx::uint256>(accounts_.balance_at(coinbase_idx));
        accounts_.set_balance_at(coinbase_idx,
            intx::be::store<evmc::uint256be>(bal_u + fee_u),
            tx_counter_);
    }

    return static_cast<uint64_t>(gas_used);
}

void ZiskStateDB::finalize_receipt(const evmc::Result& result,
                                   uint64_t            gas_used) noexcept {
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
    cumulative_gas_used_     += gas_used;
    rcpt.cumulative_gas_used  = cumulative_gas_used_;
    rcpt.status               = (result.status_code == EVMC_SUCCESS);
}

void ZiskStateDB::post_execute_block() noexcept {
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
        // stays in EIP-7685 type-byte order (0x00 → 0x01 → 0x02).
        collect_deposit_requests();           // EIP-6110
        collect_withdrawal_requests();        // EIP-7002
        collect_consolidation_requests();     // EIP-7251
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
    const size_t coinbase_idx = ensure_account(consensus_.beneficiary());
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
        const size_t idx = ensure_account(w.address());
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
    // valid as long as requests_hash matches the header.
    //
    // EIP-7002 validity: once the fork is active the request predeploy MUST
    // be present. If it has no code at end-of-block the block is invalid
    // (BlockException.SYSTEM_CONTRACT_EMPTY). Calling empty code would
    // otherwise "succeed" as a no-op and silently accept the block. EEST
    // test_system_contract_deployment (deploy_after_fork) exercises this.
    if (get_code_size(kWithdrawalRequestsAddress) == 0) {
        fatal("EIP-7002: withdrawal system contract empty (invalid block)");
    }
    auto result = system_call(kWithdrawalRequestsAddress, {});
    if (result.status_code != EVMC_SUCCESS || result.output_size == 0) {
        return;
    }
    std::vector<uint8_t> req;
    req.reserve(1 + result.output_size);
    req.push_back(kRequestTypeWithdrawal);
    req.insert(req.end(), result.output_data,
                          result.output_data + result.output_size);
    requests_.push_back(std::move(req));
}

void ZiskStateDB::collect_consolidation_requests() noexcept {
    // EIP-7251: same shape as EIP-7002 — canonical contract emits N ×
    // 116 bytes (20 + 48 + 48), type byte is 0x02, but consensus only
    // sees opaque bytes. See collect_withdrawal_requests() for the
    // rationale on accepting any size (test_modified_consolidation_
    // contract / test_extra_consolidations).
    //
    // EIP-7251 validity: empty consolidation system contract at end-of-block
    // ⇒ invalid block (BlockException.SYSTEM_CONTRACT_EMPTY); see
    // collect_withdrawal_requests() for the rationale.
    if (get_code_size(kConsolidationRequestsAddress) == 0) {
        fatal("EIP-7251: consolidation system contract empty (invalid block)");
    }
    auto result = system_call(kConsolidationRequestsAddress, {});
    if (result.status_code != EVMC_SUCCESS || result.output_size == 0) {
        return;
    }
    std::vector<uint8_t> req;
    req.reserve(1 + result.output_size);
    req.push_back(kRequestTypeConsolidation);
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

    evmc_message msg{};
    msg.kind         = EVMC_CALL;
    msg.sender       = kSystemAddress;
    msg.recipient    = target;
    msg.code_address = target;
    msg.input_data   = calldata.data();
    msg.input_size   = calldata.size();
    msg.gas          = kSystemCallGas;
    msg.value        = evmc::uint256be{};       // 0
    msg.depth        = 0;

    // Standard checkpoint+rollback discipline so a reverted system
    // frame doesn't leave half-written state behind. No gas
    // accounting (system calls have no sender to debit / coinbase to
    // pay); the caller may consume the result's output_data (e.g.
    // for EIP-7002 / EIP-7251 request dequeue).
    const auto cp = checkpoint();
    evmc::bytes32 entry_code_hash{};
    const auto entry_code = code_and_hash(target, entry_code_hash);
    auto result = evmc::Result{vm2_->execute2(
        &vm2_->base, &evmc::Host::get_interface(), to_context(),
        active_revision(), &msg, entry_code.data(), entry_code.size(),
        analysis_for(entry_code_hash))};
    if (result.status_code != EVMC_SUCCESS) {
        rollback(cp);
    }
    return result;
}

} // namespace zeg

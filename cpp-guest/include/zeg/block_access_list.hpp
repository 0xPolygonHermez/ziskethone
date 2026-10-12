// BlockAccessList — EIP-7928 (Amsterdam) block-level access list, built
// while the block executes.
//
// The BAL lists every account and storage slot the block loads, in address /
// slot order, with the post-value of each balance / nonce / code / slot at
// every block access index (0 = pre-execution system calls, i+1 = tx i,
// n+1 = post-execution) where it differs from its value at the start of that
// index. A slot loaded but never changed is a read.
//
// Cost model — nothing here walks the state per tx:
//   * Access: an `accessed` flag per account row / slot, set at the actual
//     state load (not at EIP-2929 warming, which also covers EIP-2930
//     prewarming and loads skipped for lack of gas). Never journaled: a load
//     in a reverted frame still counts.
//   * Changes, lazily: each account / slot keeps the period (BAL index) it was
//     last written in and its value at the start of that period. The first
//     write in a new period closes the old one — a field whose current value
//     differs from the period-start value gets one change record for the old
//     period — and opens the new one. Writes reverted or undone within a
//     period net out by construction. The final pass closes what is still
//     open.
//   * Order: the prover supplies the BAL's keys in order (the BalHint input
//     section); `ZiskStateDB::block_access_list_hash` checks the hint against
//     the accessed set in one linear pass (strictly increasing, every key
//     accessed, counts equal ⇒ exactly the accessed set) and encodes the RLP
//     in that order. No sort.
//
// Account side data is indexed by the Accounts row (rows never move). Witness
// slots keep their record id in `Storages::Mods`; slots the witness doesn't
// have (DynamicStorage, whose entries come and go with reverts and
// self-destructs) are found through `dyn_ids_`, keyed by (address, slot).

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <unordered_map>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg {

class Contracts;

class BlockAccessList {
public:
    static constexpr uint32_t kNone = UINT32_MAX;

    // One recorded change: the post-value of a field at a BAL index. Values
    // are 32-byte big-endian (a nonce in the last 8 bytes; a code change holds
    // the code hash, resolved to bytes when encoding). Singly linked per field.
    struct Change {
        uint32_t      next  = kNone;
        uint32_t      index = 0;
        evmc::bytes32 value{};
    };
    struct List {
        uint32_t head = kNone;
        uint32_t tail = kNone;
    };

    struct Account {
        bool            accessed = false;
        uint32_t        period   = kNone;  // BAL index of the open period
        evmc::uint256be pre_balance{};     // values at the start of `period`
        uint64_t        pre_nonce = 0;
        evmc::bytes32   pre_code_hash{};
        List            balance, nonce, code;
    };

    struct Slot {
        bool          accessed = false;
        uint32_t      period   = kNone;
        evmc::bytes32 key{};
        evmc::bytes32 pre{};
        List          changes;
    };

    explicit BlockAccessList(std::size_t account_capacity);

    uint32_t index() const noexcept { return index_; }
    void     set_index(uint32_t i) noexcept { index_ = i; }

    // ----- accounts (by Accounts row) -----
    void access_account(std::size_t row) noexcept {
        Account& a = accounts_[row];
        if (!a.accessed) {
            a.accessed = true;
            ++accessed_accounts_;
        }
    }
    bool account_period_open(std::size_t row) const noexcept {
        return accounts_[row].period == index_;
    }
    // Before the first write to `row` in the current period: close the old
    // period against the row's current values and open the new one with them.
    void open_account(std::size_t row, const evmc::uint256be& balance,
                      uint64_t nonce, const evmc::bytes32& code_hash);
    // Final pass: close the open period against the row's current values.
    void close_account(std::size_t row, const evmc::uint256be& balance,
                       uint64_t nonce, const evmc::bytes32& code_hash);
    const Account& account(std::size_t row) const noexcept { return accounts_[row]; }

    // ----- slots -----
    // Record for a witness slot whose id is kept by the caller (`id` is
    // updated when a record is created).
    Slot& witness_slot(uint32_t& id, const evmc::bytes32& key);
    // Record for a slot the witness doesn't have.
    Slot& dynamic_slot(const evmc::address& addr, const evmc::bytes32& key);
    // Lookup without creating; nullptr if the slot has no record.
    Slot* find_dynamic_slot(const evmc::address& addr,
                            const evmc::bytes32& key) noexcept;
    Slot&       slot(uint32_t id) noexcept { return slots_[id]; }

    void access_slot(Slot& s) noexcept {
        if (!s.accessed) {
            s.accessed = true;
            ++accessed_slots_;
        }
    }
    // Before the first write in the current period; `current` is the value
    // before the write.
    void open_slot(Slot& s, const evmc::bytes32& current) {
        if (s.period == index_) return;
        close_slot(s, current);
        s.pre    = current;
        s.period = index_;
    }
    void close_slot(Slot& s, const evmc::bytes32& current) {
        if (s.period != kNone && current != s.pre) {
            push(s.changes, s.period, current);
        }
        s.period = kNone;
    }

    std::size_t accessed_accounts() const noexcept { return accessed_accounts_; }
    std::size_t accessed_slots   () const noexcept { return accessed_slots_; }

    // ----- encoding -----
    // One account of the final BAL, resolved in BAL order.
    struct Entry {
        const evmc::address* address;
        const Account*       account;
        std::span<const Slot* const> slots;  // in slot order, changed and read
    };
    // keccak256(rlp(BAL)) over `entries` (already in BAL order, all periods
    // closed). Code changes are resolved to bytes through `contracts`.
    evmc::bytes32 hash(std::span<const Entry> entries,
                       const Contracts& contracts) const;
    // DEBUG (ZEG_DUMP_BAL): print the BAL as text to stderr.
    void dump(std::span<const Entry> entries, const Contracts& contracts) const;

private:
    void push(List& l, uint32_t index, const evmc::bytes32& value);

    struct Key {
        evmc::address address;
        uint32_t      pad = 0;
        evmc::bytes32 position;
        Key(const evmc::address& a, const evmc::bytes32& p) noexcept
            : address(a), position(p) {}
    };
    static_assert(sizeof(Key) == 24 + 32, "Key must have no tail padding");
    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept {
            uint64_t a, p;
            std::memcpy(&a, k.address.bytes + 12, 8);
            std::memcpy(&p, k.position.bytes + 24, 8);
            return static_cast<std::size_t>(a ^ p);
        }
    };
    struct KeyEq {
        bool operator()(const Key& x, const Key& y) const noexcept {
            return std::memcmp(&x, &y, sizeof(Key)) == 0;
        }
    };

    uint32_t             index_ = 0;
    std::vector<Account> accounts_;
    std::vector<Slot>    slots_;
    std::vector<Change>  changes_;
    std::unordered_map<Key, uint32_t, KeyHash, KeyEq> dyn_ids_;
    std::size_t          accessed_accounts_ = 0;
    std::size_t          accessed_slots_    = 0;
};

// BalHint — the BalHint input section (format v11): the BAL's keys in order.
//
//   u64 n_accounts
//   per account: address (20 B) + u32-le n_slots + n_slots × slot (32 B BE)
//
// Every record is a multiple of 8 bytes. The view only parses the framing;
// ZiskStateDB checks the keys against the accessed set.
class BalHint {
public:
    struct Account {
        const evmc::address*     address;
        std::span<const evmc::bytes32> slots;
    };

    explicit BalHint(const uint8_t*& cursor);

    std::span<const Account> accounts() const noexcept { return accounts_; }
    std::size_t              slot_count() const noexcept { return slot_count_; }

private:
    std::vector<Account> accounts_;
    std::size_t          slot_count_ = 0;
};

} // namespace zeg

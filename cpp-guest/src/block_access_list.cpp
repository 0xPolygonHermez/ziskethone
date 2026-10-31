#include "zeg/block_access_list.hpp"

#include <cstdio>

#include "zeg/contracts.hpp"
#include "zeg/fatal.hpp"
#include "zeg/keccak.hpp"
#include "zeg/rlp.hpp"

namespace zeg {

namespace {

// keccak256 of the empty byte string.
constexpr evmc::bytes32 kEmptyCodeHash{{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
}};

evmc::bytes32 nonce_value(uint64_t nonce) noexcept {
    evmc::bytes32 v{};
    for (int i = 0; i < 8; ++i) v.bytes[31 - i] = static_cast<uint8_t>(nonce >> (8 * i));
    return v;
}

// Encoded size of a 32-byte big-endian value as a minimal RLP integer.
std::size_t int_size(const evmc::bytes32& v) noexcept {
    const std::size_t start = rlp::detail::u256_significant_start(v.bytes);
    const std::size_t len   = 32 - start;
    return (len == 1 && v.bytes[31] < 0x80) ? 1 : 1 + len;
}
std::size_t write_int(uint8_t* dst, const evmc::bytes32& v) noexcept {
    const std::size_t start = rlp::detail::u256_significant_start(v.bytes);
    return rlp::write_string(dst, v.bytes + start, 32 - start);
}
// Encoded size of a byte string (a single byte < 0x80 is its own encoding).
std::size_t str_size(std::span<const uint8_t> s) noexcept {
    return (s.size() == 1 && s[0] < 0x80) ? 1 : rlp::item_size(s.size());
}
std::size_t index_size(uint32_t i) noexcept { return i < 0x80 ? 1 : (i < 0x100 ? 2 : (i < 0x10000 ? 3 : (i < 0x1000000 ? 4 : 5))); }

std::size_t list_header(uint8_t* dst, std::size_t payload_len) noexcept {
    return rlp::detail::make_header<0xc0, 0xf7>(dst, payload_len);
}

}  // namespace

BlockAccessList::BlockAccessList(std::size_t account_capacity, std::size_t slot_capacity)
    : accounts_(account_capacity) {
    slots_.reserve(slot_capacity);
}

void BlockAccessList::push(List& l, uint32_t index, const evmc::bytes32& value) {
    const auto id = static_cast<uint32_t>(changes_.size());
    changes_.push_back(Change{kNone, index, value});
    if (l.tail == kNone) {
        l.head = id;
    } else {
        changes_[l.tail].next = id;
    }
    l.tail = id;
}

void BlockAccessList::close_account(std::size_t row, const evmc::uint256be& balance,
                                    uint64_t nonce, const evmc::bytes32& code_hash) {
    Account& a = accounts_[row];
    if (a.period == kNone) return;
    if (balance != a.pre_balance) {
        evmc::bytes32 v;
        std::memcpy(v.bytes, balance.bytes, 32);
        push(a.balance, a.period, v);
    }
    if (nonce != a.pre_nonce) push(a.nonce, a.period, nonce_value(nonce));
    if (code_hash != a.pre_code_hash) push(a.code, a.period, code_hash);
    a.period = kNone;
}

void BlockAccessList::open_account(std::size_t row, const evmc::uint256be& balance,
                                   uint64_t nonce, const evmc::bytes32& code_hash) {
    close_account(row, balance, nonce, code_hash);
    Account& a      = accounts_[row];
    a.pre_balance   = balance;
    a.pre_nonce     = nonce;
    a.pre_code_hash = code_hash;
    a.period        = index_;
}

BlockAccessList::Slot& BlockAccessList::witness_slot(uint32_t& id, const evmc::bytes32& key) {
    if (id == kNone) {
        id = static_cast<uint32_t>(slots_.size());
        slots_.push_back(Slot{});
        slots_.back().key = key;
    }
    return slots_[id];
}

// ----- encoding --------------------------------------------------------------
//
// AccountChanges = [address, storage_changes, storage_reads, balance_changes,
//                   nonce_changes, code_changes]
//   storage_changes = [[slot, [[index, value], ...]], ...]   (changed slots)
//   storage_reads   = [slot, ...]                            (unchanged slots)
//   *_changes       = [[index, value], ...]
// Integers are minimal-length; code is a byte string. Two passes: sizes, then
// bytes into one buffer, then one keccak.

namespace {

struct Sizer {
    const std::vector<BlockAccessList::Change>& changes;
    const Contracts&                            contracts;

    std::span<const uint8_t> code_of(const evmc::bytes32& hash) const {
        if (hash == kEmptyCodeHash) return {};
        const auto& c = contracts.by_hash(hash);
        return {c.code, static_cast<std::size_t>(c.code_size)};
    }
    // Payload of a change list; `kind` 0 = integer value, 1 = code.
    std::size_t list_payload(const BlockAccessList::List& l, int kind) const {
        std::size_t n = 0;
        for (uint32_t id = l.head; id != BlockAccessList::kNone; id = changes[id].next) {
            const auto& c = changes[id];
            const std::size_t v = kind == 0 ? int_size(c.value) : str_size(code_of(c.value));
            n += rlp::item_size(index_size(c.index) + v);
        }
        return n;
    }
};

}  // namespace

std::vector<uint8_t> BlockAccessList::encode(std::span<const Entry> entries,
                                             const Contracts& contracts) const {
    const Sizer sz{changes_, contracts};

    // Pass 1: sizes.
    struct Sizes {
        std::size_t sc, sr, bal, nonce, code, payload;
    };
    std::vector<Sizes> sizes(entries.size());
    std::size_t total = 0;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const Entry& e = entries[i];
        Sizes&       s = sizes[i];
        s.sc = s.sr = 0;
        for (const Slot* sl : e.slots) {
            if (sl->changes.head == kNone) {
                s.sr += int_size(sl->key);
            } else {
                s.sc += rlp::item_size(int_size(sl->key) +
                                       rlp::item_size(sz.list_payload(sl->changes, 0)));
            }
        }
        s.bal   = sz.list_payload(e.account->balance, 0);
        s.nonce = sz.list_payload(e.account->nonce, 0);
        s.code  = sz.list_payload(e.account->code, 1);
        s.payload = 21 + rlp::item_size(s.sc) + rlp::item_size(s.sr) +
                    rlp::item_size(s.bal) + rlp::item_size(s.nonce) +
                    rlp::item_size(s.code);
        total += rlp::item_size(s.payload);
    }

    // Pass 2: bytes.
    std::vector<uint8_t> buf(rlp::item_size(total));
    uint8_t* p = buf.data();
    p += list_header(p, total);
    auto write_changes = [&](const List& l, std::size_t payload, int kind) {
        p += list_header(p, payload);
        for (uint32_t id = l.head; id != kNone; id = changes_[id].next) {
            const Change& c = changes_[id];
            const auto    code = kind == 1 ? sz.code_of(c.value) : std::span<const uint8_t>{};
            const std::size_t v = kind == 0 ? int_size(c.value) : str_size(code);
            p += list_header(p, index_size(c.index) + v);
            p += rlp::write_u64(p, c.index);
            p += kind == 0 ? write_int(p, c.value)
                           : rlp::write_string(p, code.data(), code.size());
        }
    };
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const Entry& e = entries[i];
        const Sizes& s = sizes[i];
        p += list_header(p, s.payload);
        p += rlp::write_string(p, e.address->bytes, 20);
        p += list_header(p, s.sc);
        for (const Slot* sl : e.slots) {
            if (sl->changes.head == kNone) continue;
            const std::size_t cl = sz.list_payload(sl->changes, 0);
            p += list_header(p, int_size(sl->key) + rlp::item_size(cl));
            p += write_int(p, sl->key);
            write_changes(sl->changes, cl, 0);
        }
        p += list_header(p, s.sr);
        for (const Slot* sl : e.slots) {
            if (sl->changes.head == kNone) p += write_int(p, sl->key);
        }
        write_changes(e.account->balance, s.bal, 0);
        write_changes(e.account->nonce, s.nonce, 0);
        write_changes(e.account->code, s.code, 1);
    }
    if (p != buf.data() + buf.size()) fatal("BAL: encoder size mismatch");
    return buf;
}

void BlockAccessList::dump(std::span<const Entry> entries,
                           const Contracts& contracts) const {
    auto hex_int = [](const evmc::bytes32& v) {
        std::size_t s = rlp::detail::u256_significant_start(v.bytes);
        std::fprintf(stderr, "0x");
        if (s == 32) { std::fprintf(stderr, "0"); return; }
        bool first = true;
        for (; s < 32; ++s) {
            std::fprintf(stderr, first ? "%x" : "%02x", v.bytes[s]);
            first = false;
        }
    };
    auto list = [&](const char* tag, const List& l, bool code) {
        for (uint32_t id = l.head; id != kNone; id = changes_[id].next) {
            std::fprintf(stderr, "  %s %u ", tag, changes_[id].index);
            if (code) {
                std::fprintf(stderr, "0x");
                if (changes_[id].value != kEmptyCodeHash) {
                    const auto& c = contracts.by_hash(changes_[id].value);
                    for (uint64_t k = 0; k < c.code_size; ++k) std::fprintf(stderr, "%02x", c.code[k]);
                }
            } else {
                hex_int(changes_[id].value);
            }
            std::fprintf(stderr, "\n");
        }
    };
    for (const Entry& e : entries) {
        std::fprintf(stderr, "A 0x");
        for (uint8_t b : e.address->bytes) std::fprintf(stderr, "%02x", b);
        std::fprintf(stderr, "\n");
        for (const Slot* sl : e.slots) {
            if (sl->changes.head == kNone) {
                std::fprintf(stderr, "  R "); hex_int(sl->key); std::fprintf(stderr, "\n");
                continue;
            }
            for (uint32_t id = sl->changes.head; id != kNone; id = changes_[id].next) {
                std::fprintf(stderr, "  S "); hex_int(sl->key);
                std::fprintf(stderr, " %u ", changes_[id].index); hex_int(changes_[id].value);
                std::fprintf(stderr, "\n");
            }
        }
        list("B", e.account->balance, false);
        list("N", e.account->nonce, false);
        list("C", e.account->code, true);
    }
}

} // namespace zeg

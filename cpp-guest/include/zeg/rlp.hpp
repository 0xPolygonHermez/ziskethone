// Minimal RLP (Recursive Length Prefix) encoder for the ZisK guest.
//
// We only need encoding (the guest never has to decode RLP from untrusted
// input — the trie node hashes happen on data we constructed). The four
// public entry points cover everything the state-root walker needs:
//
//   encode(BytesView)          - byte string
//   encode_u64(uint64_t)       - integer string (big-endian, trimmed)
//   encode_u256(uint256be)     - integer string (big-endian, trimmed)
//   encode_list(items)         - wrap N already-RLP-encoded items as a list

#pragma once

#include <cstdint>
#include <initializer_list>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg::rlp {

using Bytes     = std::vector<uint8_t>;
using BytesView = std::span<const uint8_t>;

// Encode a byte string. A single byte < 0x80 encodes as itself; longer
// strings get a 1-byte short header (≤ 55 B) or a multi-byte long header.
Bytes encode(BytesView data);

// Encode a uint64 as an RLP string (big-endian, leading-zero trimmed —
// so 0 encodes as the empty string 0x80, 1 as the single byte 0x01, etc.).
Bytes encode_u64(uint64_t v);

// Encode an evmc::uint256be (32-byte big-endian) as an RLP string with
// leading zeros trimmed.
Bytes encode_u256(const evmc::uint256be& v);

// Wrap N already-RLP-encoded items into an RLP list. Caller supplies the
// items already encoded (because each item is typically encoded with the
// matching `encode*` overload — the list helper only handles the wrapper).
Bytes encode_list(std::initializer_list<BytesView> items);

// Runtime-sized sibling of `encode_list`: wrap an already-concatenated
// payload of pre-encoded RLP items. Used by callers that build the
// payload incrementally (e.g. receipts trie, log topics list) where the
// item count isn't known at compile time.
Bytes encode_list_payload(BytesView payload);

// ----- decoder ---------------------------------------------------------------
//
// Minimal RLP reader: enough to walk a transaction envelope, a block
// header, or any other RLP blob without allocations. The decoder only
// looks at the bytes it's pointed at; callers handle iteration.

enum class ItemKind : uint8_t { String, List };

struct Item {
    ItemKind  kind;
    BytesView raw;        // full encoded item: header + payload
    BytesView payload;    // inner bytes (no header)
};

// Decode one RLP item starting at `data`. Aborts via zeg::fatal on
// malformed or truncated input. Tail bytes after the item are not
// consumed (the caller decides how many items to read).
Item decode_item(BytesView data);

// Typed decoders for RLP scalar fields. Expect `it.kind` == String
// and abort via zeg::fatal otherwise (or if the payload exceeds the
// scalar's width). `as_u256` left-pads into a 32-byte big-endian
// slot; `as_u64` interprets the payload as a trimmed big-endian
// unsigned integer.
evmc::uint256be as_u256(const Item& it);
uint64_t        as_u64 (const Item& it);

// Iterator over the items inside a list's payload. Construct with the
// payload returned by a `List`-kind `decode_item` (i.e. with `kind` set
// to `List`), then call `next()` until `has_next()` is false.
class ListIter {
public:
    explicit ListIter(BytesView list_payload) noexcept : remaining_(list_payload) {}

    bool has_next() const noexcept { return !remaining_.empty(); }

    // Decode and consume one item from the payload. Aborts via
    // zeg::fatal if called when `has_next()` is false.
    Item next();

private:
    BytesView remaining_;
};

} // namespace zeg::rlp

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

// ----- allocation-free encoding ----------------------------------------------
//
// The `encode*` forms above allocate per item, which suits one-shot callers but
// not the state-root walk. These write into a caller buffer instead. A composite
// item is written payload-first, then its header is prepended into space the
// caller reserved ahead of it — the header's length depends on the payload's, so
// it cannot be written up front. `prepend_*` return the new start offset.

namespace detail {

// Header into a caller buffer (max 5 B); returns its length. Short form is
// `ShortBase + len`, long form `LongBase + len-of-len` then the length.
template <uint8_t ShortBase, uint8_t LongBase>
inline std::size_t make_header(uint8_t hdr[5], std::size_t payload_len) {
    if (payload_len <= 55) {
        hdr[0] = static_cast<uint8_t>(ShortBase + payload_len);
        return 1;
    }
    std::size_t n = 1;
    for (std::size_t v = payload_len >> 8; v; v >>= 8) ++n;
    hdr[0] = static_cast<uint8_t>(LongBase + n);
    for (std::size_t k = 0; k < n; ++k) {
        hdr[1 + k] = static_cast<uint8_t>(payload_len >> (8 * (n - 1 - k)));
    }
    return 1 + n;
}

// Offset of the first significant byte of a 32-byte value (32 for zero, i.e.
// the empty RLP string). Zero limbs skip 8 bytes at a time, then clz.
inline std::size_t u256_significant_start(const uint8_t bytes[32]) {
    std::size_t start = 0;
    for (; start < 32; start += 8) {
        uint64_t w;
        __builtin_memcpy(&w, bytes + start, sizeof(w));
        if (w) {
            start += static_cast<std::size_t>(__builtin_clzll(__builtin_bswap64(w))) >> 3;
            break;
        }
    }
    return start;
}

template <uint8_t ShortBase, uint8_t LongBase>
inline std::size_t prepend(uint8_t* buf, std::size_t start, std::size_t end) {
    const std::size_t len = end - start;
    if (len <= 55) {  // the common node shape
        buf[start - 1] = static_cast<uint8_t>(ShortBase + len);
        return start - 1;
    }
    uint8_t hdr[5];
    const std::size_t n = make_header<ShortBase, LongBase>(hdr, len);
    __builtin_memcpy(buf + start - n, hdr, n);
    return start - n;
}

}  // namespace detail

// Return how many bytes were written at `dst`.
inline std::size_t write_string(uint8_t* dst, const uint8_t* src, std::size_t len) {
    if (len == 1 && src[0] < 0x80) {  // single byte < 0x80 encodes as itself
        dst[0] = src[0];
        return 1;
    }
    if (len <= 55) {  // every node field takes this path
        dst[0] = static_cast<uint8_t>(0x80 + len);
        __builtin_memcpy(dst + 1, src, len);
        return 1 + len;
    }
    uint8_t hdr[5];
    const std::size_t n = detail::make_header<0x80, 0xb7>(hdr, len);
    __builtin_memcpy(dst, hdr, n);
    __builtin_memcpy(dst + n, src, len);
    return n + len;
}

inline std::size_t write_u64(uint8_t* dst, uint64_t v) {
    uint8_t be[8];
    const uint64_t swapped = __builtin_bswap64(v);
    __builtin_memcpy(be, &swapped, sizeof(be));
    const std::size_t start = v ? (static_cast<std::size_t>(__builtin_clzll(v)) >> 3) : 8;
    return write_string(dst, be + start, 8 - start);
}

inline std::size_t write_u256(uint8_t* dst, const evmc::uint256be& v) {
    const std::size_t start = detail::u256_significant_start(v.bytes);
    return write_string(dst, v.bytes + start, 32 - start);
}

// Wrap `buf[start, end)`, writing the header just below `start`.
inline std::size_t prepend_list(uint8_t* buf, std::size_t start, std::size_t end) {
    return detail::prepend<0xc0, 0xf7>(buf, start, end);
}

inline std::size_t prepend_string(uint8_t* buf, std::size_t start, std::size_t end) {
    if (end - start == 1 && buf[start] < 0x80) {
        return start;  // bare byte, as above
    }
    return detail::prepend<0x80, 0xb7>(buf, start, end);
}

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

#include "zeg/rlp.hpp"

#include <cstring>

#include "zeg/fatal.hpp"

namespace zeg::rlp {

namespace {

// Big-endian byte count needed to represent `len` (1..4 bytes covers
// every payload size we'll ever produce).
uint8_t be_length_bytes(size_t len) {
    if (len <= 0xff)        return 1;
    if (len <= 0xffff)      return 2;
    if (len <= 0xffffff)    return 3;
    return 4;
}

// Append `len` as big-endian, using exactly `n` bytes.
void append_be(Bytes& out, size_t len, uint8_t n) {
    for (int8_t i = static_cast<int8_t>(n) - 1; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>(len >> (8 * i)));
    }
}

// Append a header for either a short string (ShortBase, ≤ 55 B payload)
// or a long string (LongBase + len-of-len).
template <uint8_t ShortBase, uint8_t LongBase>
void append_header(Bytes& out, size_t payload_len) {
    if (payload_len <= 55) {
        out.push_back(static_cast<uint8_t>(ShortBase + payload_len));
    } else {
        const uint8_t n = be_length_bytes(payload_len);
        out.push_back(static_cast<uint8_t>(LongBase + n));
        append_be(out, payload_len, n);
    }
}

} // namespace

Bytes encode(BytesView data) {
    Bytes out;
    // Single byte < 0x80 encodes as the byte itself.
    if (data.size() == 1 && data[0] < 0x80) {
        out.push_back(data[0]);
        return out;
    }
    out.reserve(1 + (data.size() > 55 ? 4 : 0) + data.size());
    append_header<0x80, 0xb7>(out, data.size());
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

Bytes encode_u64(uint64_t v) {
    uint8_t be[8];
    for (int i = 7; i >= 0; --i) {
        be[i] = static_cast<uint8_t>(v & 0xff);
        v >>= 8;
    }
    size_t start = 0;
    while (start < 8 && be[start] == 0) ++start;
    return encode(BytesView{be + start, 8 - start});
}

Bytes encode_u256(const evmc::uint256be& v) {
    size_t start = 0;
    while (start < 32 && v.bytes[start] == 0) ++start;
    return encode(BytesView{v.bytes + start, 32 - start});
}

Bytes encode_list(std::initializer_list<BytesView> items) {
    size_t payload_len = 0;
    for (const auto& it : items) payload_len += it.size();

    Bytes out;
    out.reserve(1 + (payload_len > 55 ? 4 : 0) + payload_len);
    append_header<0xc0, 0xf7>(out, payload_len);
    for (const auto& it : items) {
        out.insert(out.end(), it.begin(), it.end());
    }
    return out;
}

Bytes encode_list_payload(BytesView payload) {
    Bytes out;
    out.reserve(1 + (payload.size() > 55 ? 4 : 0) + payload.size());
    append_header<0xc0, 0xf7>(out, payload.size());
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// ----- decoder -------------------------------------------------------------

namespace {

// Read `n` big-endian bytes starting at `p` into a size_t.
size_t read_be(const uint8_t* p, size_t n) {
    size_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        v = (v << 8) | p[i];
    }
    return v;
}

} // namespace

Item decode_item(BytesView data) {
    if (data.empty()) {
        fatal("rlp::decode_item: empty input");
    }
    const uint8_t b = data[0];

    if (b < 0x80) {
        // Single-byte string whose value is the byte itself. Raw and
        // payload both point at that one byte (no separate header).
        return Item{ItemKind::String,
                    BytesView{data.data(), 1},
                    BytesView{data.data(), 1}};
    }
    if (b <= 0xb7) {
        const size_t payload_len = static_cast<size_t>(b - 0x80);
        const size_t total       = 1 + payload_len;
        if (data.size() < total) {
            fatal("rlp::decode_item: short string truncated");
        }
        return Item{ItemKind::String,
                    BytesView{data.data(), total},
                    BytesView{data.data() + 1, payload_len}};
    }
    if (b <= 0xbf) {
        const size_t len_of_len = static_cast<size_t>(b - 0xb7);
        if (data.size() < 1 + len_of_len) {
            fatal("rlp::decode_item: long string length truncated");
        }
        const size_t payload_len = read_be(data.data() + 1, len_of_len);
        const size_t total       = 1 + len_of_len + payload_len;
        if (data.size() < total) {
            fatal("rlp::decode_item: long string body truncated");
        }
        return Item{ItemKind::String,
                    BytesView{data.data(), total},
                    BytesView{data.data() + 1 + len_of_len, payload_len}};
    }
    if (b <= 0xf7) {
        const size_t payload_len = static_cast<size_t>(b - 0xc0);
        const size_t total       = 1 + payload_len;
        if (data.size() < total) {
            fatal("rlp::decode_item: short list truncated");
        }
        return Item{ItemKind::List,
                    BytesView{data.data(), total},
                    BytesView{data.data() + 1, payload_len}};
    }
    // 0xf8..0xff: long list.
    const size_t len_of_len = static_cast<size_t>(b - 0xf7);
    if (data.size() < 1 + len_of_len) {
        fatal("rlp::decode_item: long list length truncated");
    }
    const size_t payload_len = read_be(data.data() + 1, len_of_len);
    const size_t total       = 1 + len_of_len + payload_len;
    if (data.size() < total) {
        fatal("rlp::decode_item: long list body truncated");
    }
    return Item{ItemKind::List,
                BytesView{data.data(), total},
                BytesView{data.data() + 1 + len_of_len, payload_len}};
}

Item ListIter::next() {
    if (remaining_.empty()) {
        fatal("rlp::ListIter::next: payload exhausted");
    }
    const Item it = decode_item(remaining_);
    const size_t adv = it.raw.size();
    remaining_    = BytesView{remaining_.data() + adv,
                              remaining_.size() - adv};
    return it;
}

evmc::uint256be as_u256(const Item& it) {
    if (it.kind != ItemKind::String) {
        fatal("rlp::as_u256: expected RLP string");
    }
    if (it.payload.size() > 32) {
        fatal("rlp::as_u256: payload > 32 bytes");
    }
    evmc::uint256be out{};
    const size_t off = 32 - it.payload.size();
    std::memcpy(out.bytes + off, it.payload.data(), it.payload.size());
    return out;
}

uint64_t as_u64(const Item& it) {
    if (it.kind != ItemKind::String) {
        fatal("rlp::as_u64: expected RLP string");
    }
    if (it.payload.size() > 8) {
        fatal("rlp::as_u64: payload > 8 bytes");
    }
    uint64_t v = 0;
    for (size_t i = 0; i < it.payload.size(); ++i) {
        v = (v << 8) | it.payload[i];
    }
    return v;
}

} // namespace zeg::rlp

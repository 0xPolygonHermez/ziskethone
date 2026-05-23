#include "zeg/rlp.hpp"

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

} // namespace zeg::rlp

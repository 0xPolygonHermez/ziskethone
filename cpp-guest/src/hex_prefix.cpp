#include "zeg/hex_prefix.hpp"

#include "zeg/fatal.hpp"

namespace zeg {

HpBytes hex_prefix(std::span<const uint8_t> nibbles, bool leaf) {
    if (nibbles.size() > HpBytes::kMaxNibbles) {
        fatal("hex_prefix: path longer than 64 nibbles");
    }
    const bool odd       = (nibbles.size() & 1U) == 1U;
    const uint8_t leaf_b = leaf ? 0x20 : 0x00;

    HpBytes out;

    size_t i = 0;
    if (odd) {
        out.buf[out.len++] = static_cast<uint8_t>(leaf_b | 0x10 | (nibbles[0] & 0x0f));
        i = 1;
    } else {
        out.buf[out.len++] = leaf_b;
    }
    while (i < nibbles.size()) {
        const uint8_t hi = nibbles[i]     & 0x0f;
        const uint8_t lo = nibbles[i + 1] & 0x0f;
        out.buf[out.len++] = static_cast<uint8_t>((hi << 4) | lo);
        i += 2;
    }
    return out;
}

} // namespace zeg

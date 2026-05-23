#include "zeg/hex_prefix.hpp"

namespace zeg {

std::vector<uint8_t> hex_prefix(std::span<const uint8_t> nibbles, bool leaf) {
    const bool odd       = (nibbles.size() & 1U) == 1U;
    const uint8_t leaf_b = leaf ? 0x20 : 0x00;

    std::vector<uint8_t> out;
    out.reserve(nibbles.size() / 2 + 1);

    size_t i = 0;
    if (odd) {
        out.push_back(static_cast<uint8_t>(leaf_b | 0x10 | (nibbles[0] & 0x0f)));
        i = 1;
    } else {
        out.push_back(leaf_b);
    }
    while (i < nibbles.size()) {
        const uint8_t hi = nibbles[i]     & 0x0f;
        const uint8_t lo = nibbles[i + 1] & 0x0f;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        i += 2;
    }
    return out;
}

} // namespace zeg

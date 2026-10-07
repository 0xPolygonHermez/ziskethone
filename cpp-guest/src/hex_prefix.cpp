#include "zeg/hex_prefix.hpp"

#include "zeg/fatal.hpp"

#include <cstring>

namespace zeg {

HpBytes hex_prefix(const PackedPath& path, bool leaf) {
    const std::size_t n = path.size();
    if (n > HpBytes::kMaxNibbles) {
        fatal("hex_prefix: path longer than 64 nibbles");
    }
    const bool    odd    = (n & 1U) == 1U;
    const uint8_t leaf_b = leaf ? 0x20 : 0x00;

    HpBytes out;

    // Fast path: the packing already starts on the half HP needs, so the flag
    // byte is written and the rest of the path is copied verbatim.
    //   odd  -> [flags|p0][p1 p2]...  and the path starts in a low half
    //   even -> [flags|0 ][p0 p1]...  and the path starts in a high half
    if (path.aligned_for_hp()) {
        if (odd) {
            out.buf[0] = static_cast<uint8_t>(leaf_b | 0x10 | (path.at(0) & 0x0f));
            const std::size_t rest = (n - 1) / 2;      // whole bytes after p0
            std::memcpy(out.buf + 1, path.data() + 1, rest);
            out.len = static_cast<uint8_t>(1 + rest);
        } else {
            out.buf[0] = leaf_b;
            const std::size_t rest = n / 2;
            std::memcpy(out.buf + 1, path.data(), rest);
            out.len = static_cast<uint8_t>(1 + rest);
        }
        return out;
    }

    // Slow path: packed on the wrong half (an extension path read from the
    // witness at an odd length), so shift it across.
    std::size_t i = 0;
    if (odd) {
        out.buf[out.len++] = static_cast<uint8_t>(leaf_b | 0x10 | (path.at(0) & 0x0f));
        i = 1;
    } else {
        out.buf[out.len++] = leaf_b;
    }
    while (i < n) {
        const uint8_t hi = path.at(i)     & 0x0f;
        const uint8_t lo = path.at(i + 1) & 0x0f;
        out.buf[out.len++] = static_cast<uint8_t>((hi << 4) | lo);
        i += 2;
    }
    return out;
}

HpBytes hex_prefix(std::span<const uint8_t> nibbles, bool leaf) {
    if (nibbles.size() > HpBytes::kMaxNibbles) {
        fatal("hex_prefix: path longer than 64 nibbles");
    }
    const bool    odd    = (nibbles.size() & 1U) == 1U;
    const uint8_t leaf_b = leaf ? 0x20 : 0x00;

    HpBytes out;
    std::size_t i = 0;
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

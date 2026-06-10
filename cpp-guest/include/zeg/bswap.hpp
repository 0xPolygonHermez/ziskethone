// zeg/bswap.hpp — the 64-bit byte swap. The single implementation shared by
// zevm (u256.hpp: byteswap256 / u256_from_be / u256_to_be) and by the ZisK
// runtime's libgcc ABI symbol __bswapdi2 (zisk/compiler_rt.cpp), which is a
// one-line wrapper around it.
//
// Inline: the ZisK target (rv64ima, no Zbb) has no byte-swap instruction, so
// this is the soft shift/mask sequence; inlining drops the call/ret an
// out-of-line helper would cost per limb.

#pragma once

#include <cstdint>

namespace zeg {

// Zero shortcut: zevm's lazy endianness swaps whole 256-bit words (four of
// these per conversion) and most EVM values are small, so typically 3 of 4
// limbs are zero — those exit in ~2 steps instead of the ~20-op body, while
// nonzero limbs pay a single untaken branch.
inline uint64_t bswap64(uint64_t x) {
    if (x == 0) return 0;
    return  (x >> 56) | ((x >> 40) & 0xFF00ull) | ((x >> 24) & 0xFF0000ull) |
            ((x >> 8) & 0xFF000000ull) | ((x << 8) & 0xFF00000000ull) |
            ((x << 24) & 0xFF0000000000ull) | ((x << 40) & 0xFF000000000000ull) |
            (x << 56);
}

}  // namespace zeg

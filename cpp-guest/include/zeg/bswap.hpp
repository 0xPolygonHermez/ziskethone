// zeg/bswap.hpp — the 64-bit byte swap. The single implementation shared by
// zevm (u256.hpp: byteswap256 / u256_from_be / u256_to_be) and by the ZisK
// runtime's libgcc ABI symbol __bswapdi2 (zisk/runtime.cpp), which is a
// one-line wrapper around it.
//
// Inline: without Zbb the ZisK target has no byte-swap instruction, so this is
// the soft shift/mask sequence; inlining drops the call/ret an out-of-line
// helper would cost per limb.
//
// Three variants, selected at compile time:
//
//  1. No Zbb (__riscv_zbb undefined, e.g. -DZISK_MARCH=rv64ima_zicsr): the
//     portable zero-shortcut shift/mask sequence below.
//
//  2. Zbb available (the default guest march, see zisk/toolchain.cmake) and
//     ZEG_BSWAP_BUILTIN unset (the default): SAME zero-shortcut, but the
//     nonzero path issues `rev8` via inline asm instead of the shift/mask
//     tree. This is NOT the same as just calling __builtin_bswap64: GCC's
//     tree-bswap idiom pass recognizes "x==0 ? 0 : shift/mask-tree" (or an
//     equivalent __builtin_bswap64 call, since it also knows bswap64(0)==0)
//     as a whole and rewrites it to an UNCONDITIONAL `rev8`, silently
//     deleting the shortcut — confirmed by disassembling both forms with
//     riscv-none-elf-gcc 14.3.0 -O3. Since most EVM values are small (3 of 4
//     limbs in a 256-bit word are typically zero), that fold regresses the
//     common case (flat 13-op zisk cost for `rev8` vs. this file's ~2-op
//     zero exit). Inline asm is opaque to that pass, so the branch survives:
//     ~2 zisk ops when zero, ~14 (branch + `rev8`'s 13-op transpiler
//     decomposition) when not — strictly better than variant 3 below and
//     also better than variant 1's ~33-op nonzero path.
//
//  3. ZEG_BSWAP_BUILTIN defined: plain __builtin_bswap64, no shortcut — the
//     "let the compiler fold it" variant purely for A/B step-count
//     comparison against variant 2; expect it to lose on zero-heavy blocks
//     and win only if a call site's inputs are reliably nonzero (e.g. a full
//     256-bit hash).
#pragma once

#include <cstdint>

namespace zeg {

#if defined(ZEG_BSWAP_BUILTIN)

inline uint64_t bswap64(uint64_t x) { return __builtin_bswap64(x); }

#elif defined(__riscv_zbb)

inline uint64_t bswap64(uint64_t x) {
    if (x == 0) return 0;
    uint64_t r;
    asm("rev8 %0, %1" : "=r"(r) : "r"(x));
    return r;
}

#else

// Zero shortcut: zevm's lazy endianness swaps whole 256-bit words (four of
// these per conversion) and most EVM values are small, so typically 3 of 4
// limbs are zero — those exit in ~2 steps instead of the ~33-op body, while
// nonzero limbs pay a single untaken branch.
inline uint64_t bswap64(uint64_t x) {
    if (x == 0) return 0;
    return  (x >> 56) | ((x >> 40) & 0xFF00ull) | ((x >> 24) & 0xFF0000ull) |
            ((x >> 8) & 0xFF000000ull) | ((x << 8) & 0xFF00000000ull) |
            ((x << 24) & 0xFF0000000000ull) | ((x << 40) & 0xFF000000000000ull) |
            (x << 56);
}

#endif

}  // namespace zeg

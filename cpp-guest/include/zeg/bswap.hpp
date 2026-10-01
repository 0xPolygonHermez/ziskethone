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
//     portable zero-shortcut shift/mask sequence below. The shortcut earns its
//     branch here — the nonzero body is ~33 zisk ops.
//
//  2. ZEG_BSWAP_BUILTIN defined (the DEFAULT, see zisk/CMakeLists.txt): plain
//     __builtin_bswap64. The guest march carries Zbb/Zbkb, so this is one
//     unconditional `rev8` — a single zisk op.
//
//  3. Zbb available and ZEG_BSWAP_BUILTIN unset: a zero shortcut whose nonzero
//     path issues `rev8` through inline asm. This was the default while `rev8`
//     still cost 13 zisk ops in the transpiler, when skipping it on a zero limb
//     (3 of 4 limbs in a 256-bit word are typically zero) beat paying it. It is
//     now a pessimization twice over, and the second reason is the larger one:
//       - `rev8` is one op, so the guard branch costs more than the work it skips;
//       - inline asm is opaque to every GCC pass, so it acts as an optimization
//         barrier. Every byteswap has to survive to the ELF. With the builtin,
//         GCC folds swap pairs, constant-folds, and sinks swaps through loads.
//     Measured A/B on block 25701329 (zevm + -mzisk-dma, two ELFs from the same
//     configure line bar this flag, both hash-verified): the builtin executes
//     980k `rev8` against the asm variant's 1.60M — 39% FEWER, not more, which is
//     the optimization barrier showing up — for -1.49% steps and -1.99% of the
//     area left once the keccak precompile is excluded. MEMORY drops 2.16%, i.e.
//     GCC also removes loads/stores around the swaps. Block 25708403 agrees at
//     about two thirds the size (-1.09% / -1.50%).
//     Keep the knob for A/B runs; do not expect it to win.
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

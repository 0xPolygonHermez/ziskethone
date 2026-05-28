// libgcc_overrides.cpp — inline replacements for the bit-counting helpers.
//
// With `-march=rv64imac_zicsr_zaamo_zalrsc` (confirmed safe to use on Zisk by
// the team), the GCC multilib resolver picks
// `lib/gcc/riscv-none-elf/15.2.0/rv64imac_zaamo_zalrsc/lp64/libgcc.a` — a
// libgcc built WITH the M extension. That alone collapses ~1800 software
// `__muldi3` / `__multi3` / `__udivdi3` / `__umoddi3` / `__divdi3` /
// `__moddi3` / `__bswapdi2` / `__bswapsi2` shift-and-add helpers down to
// native `mul`, `divu`, `remu` and inline bswap shifts — no source overrides
// needed for any of them.
//
// What no libgcc multilib in the xPack 15.2 distribution covers is the Zbb
// extension (count-leading-zeros, count-trailing-zeros, popcount). Even the
// `rv64imac` variant lacks Zbb, so `__builtin_clzll` / `__builtin_ctzll` /
// `__builtin_popcountll` still lower to libgcc out-of-line helpers
// (`__clzdi2`, `__ctzdi2`, `__popcountdi2`). The replacements below let GCC
// inline a binary search (or SWAR popcount) at every site instead of paying
// the JAL + epilogue.

#include <cstdint>

extern "C"
{
// Count leading zeros — binary search, ~10 instructions inlined per site.
int __clzdi2(uint64_t v) noexcept
{
    if (v == 0)
        return 64;
    int n = 0;
    if ((v >> 32) == 0) { n += 32; v <<= 32; }
    if ((v >> 48) == 0) { n += 16; v <<= 16; }
    if ((v >> 56) == 0) { n +=  8; v <<=  8; }
    if ((v >> 60) == 0) { n +=  4; v <<=  4; }
    if ((v >> 62) == 0) { n +=  2; v <<=  2; }
    if ((v >> 63) == 0) { n +=  1; }
    return n;
}

// Count trailing zeros — same shape, walks the low bits.
int __ctzdi2(uint64_t v) noexcept
{
    if (v == 0)
        return 64;
    int n = 0;
    if ((v & 0xFFFFFFFFULL) == 0) { n += 32; v >>= 32; }
    if ((v & 0x0000FFFFULL) == 0) { n += 16; v >>= 16; }
    if ((v & 0x000000FFULL) == 0) { n +=  8; v >>=  8; }
    if ((v & 0x0000000FULL) == 0) { n +=  4; v >>=  4; }
    if ((v & 0x00000003ULL) == 0) { n +=  2; v >>=  2; }
    if ((v & 0x00000001ULL) == 0) { n +=  1; }
    return n;
}

// SWAR popcount — 8 packed half-byte counts collapsed via one 64-bit multiply.
int __popcountdi2(uint64_t v) noexcept
{
    v = v - ((v >> 1) & 0x5555555555555555ULL);
    v = (v & 0x3333333333333333ULL) + ((v >> 2) & 0x3333333333333333ULL);
    v = (v + (v >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return static_cast<int>((v * 0x0101010101010101ULL) >> 56);
}
}  // extern "C"

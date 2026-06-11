// bitwise.cpp — comparison & bitwise-logic opcodes (0x10..0x1e: LT, GT, SLT,
// SGT, EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR, CLZ).
//
// Endianness (the stack is big-endian; see EvmState::stack):
//   * LT/GT/SLT/SGT, SHL/SHR/SAR, BYTE, CLZ — magnitude/positional, so operands
//     are loaded as little-endian (ld_le) and the result written back BE (st_le).
//   * AND/OR/XOR/NOT — bit-parallel, so endianness-agnostic: operate on the BE
//     slots in place, no conversion.
//   * ISZERO/EQ — zero and equality are the same in either representation: test
//     the BE slots directly; the 0/1 result is stored BE via st_le.
// Binary ops take a = top, b = second and push the result into b's slot.

#include "detail.hpp"

namespace zevm {

namespace {

// The boolean results 0/1, big-endian (st_le of the integer). byteswap256 of a
// constant folds, so these are compile-time constants.
inline U256 bool_be(bool v) { return v ? U256{{0, 0, 0, 0x0100000000000000ULL}} : U256{}; }

// Signed less-than (two's complement): differing signs decide it; same sign
// falls back to the unsigned comparison (which preserves the ordering).
inline bool u256_slt(const U256& a, const U256& b) {
    const bool sa = u256_sign(a), sb = u256_sign(b);
    if (sa != sb) return sa;          // a negative, b non-negative => a < b
    return u256_lt(a, b);
}

// Logical left shift by n (0..255); bits shifted out the top are dropped.
inline U256 shl(const U256& a, unsigned n) {
    U256 r{};
    if (n >= 256) return r;
    const unsigned w = n / 64, b = n % 64;
    for (unsigned i = 0; i < 4; ++i) {
        if (i + w < 4)               r.limbs[i + w]     |= a.limbs[i] << b;
        if (b && i + w + 1 < 4)      r.limbs[i + w + 1] |= a.limbs[i] >> (64 - b);
    }
    return r;
}

// Logical right shift by n (0..255).
inline U256 shr(const U256& a, unsigned n) {
    U256 r{};
    if (n >= 256) return r;
    const unsigned w = n / 64, b = n % 64;
    for (unsigned i = 0; i < 4; ++i) {
        if (i >= w)                  r.limbs[i - w]     |= a.limbs[i] >> b;
        if (b && i >= w + 1)         r.limbs[i - w - 1] |= a.limbs[i] << (64 - b);
    }
    return r;
}

// Arithmetic right shift by n: logical shift, then fill the top n bits with the
// sign bit of a.
inline U256 sar(const U256& a, unsigned n) {
    const bool neg = u256_sign(a);
    if (n >= 256) { const uint64_t f = neg ? ~0ULL : 0; return U256{{f, f, f, f}}; }
    U256 r = shr(a, n);
    if (neg && n != 0) {
        const U256 all{{~0ULL, ~0ULL, ~0ULL, ~0ULL}};
        const U256 hi = shl(all, 256 - n);   // top n bits set
        for (int i = 0; i < 4; ++i) r.limbs[i] |= hi.limbs[i];
    }
    return r;
}

// Shift amount as a clamped int: anything >= 256 is treated as 256.
inline unsigned shift_amount(const U256& s) {
    if ((s.limbs[1] | s.limbs[2] | s.limbs[3]) != 0 || s.limbs[0] >= 256) return 256;
    return static_cast<unsigned>(s.limbs[0]);
}

// 0x10 LT — unsigned a < b.
bool op_lt(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, s.stackPointer);
    const U256 b = ld_le(s, s.stackPointer + 1);
    s.stack[s.stackPointer + 1] = bool_be(u256_lt(a, b));
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x11 GT — unsigned a > b.
bool op_gt(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, s.stackPointer);
    const U256 b = ld_le(s, s.stackPointer + 1);
    s.stack[s.stackPointer + 1] = bool_be(u256_lt(b, a));
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x12 SLT — signed a < b.
bool op_slt(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, s.stackPointer);
    const U256 b = ld_le(s, s.stackPointer + 1);
    s.stack[s.stackPointer + 1] = bool_be(u256_slt(a, b));
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x13 SGT — signed a > b.
bool op_sgt(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, s.stackPointer);
    const U256 b = ld_le(s, s.stackPointer + 1);
    s.stack[s.stackPointer + 1] = bool_be(u256_slt(b, a));
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x14 EQ — a == b. Equality is representation-agnostic: compare BE slots.
bool op_eq(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const bool e = u256_eq(s.stack[s.stackPointer], s.stack[s.stackPointer + 1]);
    s.stack[s.stackPointer + 1] = bool_be(e);
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x15 ISZERO — a == 0 (unary). Zero is all-zero in either representation.
bool op_iszero(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    s.stack[s.stackPointer] = bool_be(u256_is_zero(s.stack[s.stackPointer]));
    ++s.pc;
    return true;
}

// Shared body for AND/OR/XOR: bit-parallel, so endianness-agnostic — operate on
// the big-endian slots in place; the result is big-endian too.
template <class Op>
inline bool binary_logic(EvmState& s, Op op) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    for (int i = 0; i < 4; ++i) b.limbs[i] = op(a.limbs[i], b.limbs[i]);
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x16 AND / 0x17 OR / 0x18 XOR.
bool op_and(EvmState& s) { return binary_logic(s, [](uint64_t x, uint64_t y) { return x & y; }); }
bool op_or (EvmState& s) { return binary_logic(s, [](uint64_t x, uint64_t y) { return x | y; }); }
bool op_xor(EvmState& s) { return binary_logic(s, [](uint64_t x, uint64_t y) { return x ^ y; }); }

// 0x19 NOT — bitwise complement (unary). Bit-parallel: complement the BE slot.
bool op_not(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    U256& a = s.stack[s.stackPointer];
    for (int i = 0; i < 4; ++i) a.limbs[i] = ~a.limbs[i];
    ++s.pc;
    return true;
}

// 0x1e CLZ — count leading zero bits of the 256-bit word (EIP-7939, Osaka).
// clz(0) == 256. Positional, so the operand is loaded LE; result LE -> BE.
bool op_clz(EvmState& s) {
    if (s.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_LOW;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, s.stackPointer);
    uint64_t n;  // limb[3] is most significant; higher all-zero limbs add 64 each
    if (a.limbs[3] != 0)      n =       static_cast<uint64_t>(__builtin_clzll(a.limbs[3]));
    else if (a.limbs[2] != 0) n =  64 + static_cast<uint64_t>(__builtin_clzll(a.limbs[2]));
    else if (a.limbs[1] != 0) n = 128 + static_cast<uint64_t>(__builtin_clzll(a.limbs[1]));
    else if (a.limbs[0] != 0) n = 192 + static_cast<uint64_t>(__builtin_clzll(a.limbs[0]));
    else                      n = 256;
    st_le(s, s.stackPointer, U256{{n, 0, 0, 0}});
    ++s.pc;
    return true;
}

// 0x1a BYTE — the i-th byte of x, counting from the most significant (i = 0).
// i >= 32 yields 0. Stack: i = top, x = second.
bool op_byte(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 i = ld_le(s, s.stackPointer);
    const U256 x = ld_le(s, s.stackPointer + 1);
    U256 r{};
    if ((i.limbs[1] | i.limbs[2] | i.limbs[3]) == 0 && i.limbs[0] <= 31) {
        const unsigned idx = static_cast<unsigned>(i.limbs[0]);  // 0 = most significant
        const unsigned pos = 31 - idx;                           // byte index from LSB
        r.limbs[0] = (x.limbs[pos >> 3] >> ((pos & 7) * 8)) & 0xFFULL;
    }
    st_le(s, s.stackPointer + 1, r);
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x1b SHL — value << shift. Stack: shift = top, value = second.
bool op_shl(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 sh = ld_le(s, s.stackPointer);
    const U256 v  = ld_le(s, s.stackPointer + 1);
    st_le(s, s.stackPointer + 1, shl(v, shift_amount(sh)));
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x1c SHR — logical value >> shift.
bool op_shr(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 sh = ld_le(s, s.stackPointer);
    const U256 v  = ld_le(s, s.stackPointer + 1);
    st_le(s, s.stackPointer + 1, shr(v, shift_amount(sh)));
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x1d SAR — arithmetic (sign-propagating) value >> shift.
bool op_sar(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 sh = ld_le(s, s.stackPointer);
    const U256 v  = ld_le(s, s.stackPointer + 1);
    st_le(s, s.stackPointer + 1, sar(v, shift_amount(sh)));
    ++s.stackPointer;
    ++s.pc;
    return true;
}

}  // namespace

void register_bitwise(InstrTable& t, evmc_revision rev) {
    t[0x10] = &op_lt;
    t[0x11] = &op_gt;
    t[0x12] = &op_slt;
    t[0x13] = &op_sgt;
    t[0x14] = &op_eq;
    t[0x15] = &op_iszero;
    t[0x16] = &op_and;
    t[0x17] = &op_or;
    t[0x18] = &op_xor;
    t[0x19] = &op_not;
    t[0x1a] = &op_byte;
    if (rev >= EVMC_CONSTANTINOPLE) {  // EIP-145
        t[0x1b] = &op_shl;
        t[0x1c] = &op_shr;
        t[0x1d] = &op_sar;
    }
    if (rev >= EVMC_OSAKA)  // EIP-7939
        t[0x1e] = &op_clz;
}

}  // namespace zevm

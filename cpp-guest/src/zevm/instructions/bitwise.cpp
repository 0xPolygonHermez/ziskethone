// bitwise.cpp — comparison & bitwise-logic opcodes (0x10..0x1f: LT, GT, SLT,
// SGT, EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR).
//
// All limb-level work (no 256-bit precompile needed): AND/OR/XOR/NOT are
// per-limb, comparisons walk limbs from the top, and the shifts move bits across
// the four little-endian limbs. Binary ops take a = top, b = second and push the
// result into b's slot; unary ops (ISZERO, NOT) rewrite the top in place.

#include "detail.hpp"

namespace zevm {

namespace {

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
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    b = u256_lt(a, b) ? U256{{1, 0, 0, 0}} : U256{};
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x11 GT — unsigned a > b.
bool op_gt(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    b = u256_lt(b, a) ? U256{{1, 0, 0, 0}} : U256{};
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x12 SLT — signed a < b.
bool op_slt(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    b = u256_slt(a, b) ? U256{{1, 0, 0, 0}} : U256{};
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x13 SGT — signed a > b.
bool op_sgt(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    b = u256_slt(b, a) ? U256{{1, 0, 0, 0}} : U256{};
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x14 EQ — a == b.
bool op_eq(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    b = u256_eq(a, b) ? U256{{1, 0, 0, 0}} : U256{};
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x15 ISZERO — a == 0 (unary).
bool op_iszero(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    U256& a = s.stack[s.stackPointer];
    a = u256_is_zero(a) ? U256{{1, 0, 0, 0}} : U256{};
    ++s.pc;
    return true;
}

// 0x16 AND — bitwise a & b.
bool op_and(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    for (int i = 0; i < 4; ++i) b.limbs[i] &= a.limbs[i];
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x17 OR — bitwise a | b.
bool op_or(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    for (int i = 0; i < 4; ++i) b.limbs[i] |= a.limbs[i];
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x18 XOR — bitwise a ^ b.
bool op_xor(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    for (int i = 0; i < 4; ++i) b.limbs[i] ^= a.limbs[i];
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x19 NOT — bitwise complement (unary).
bool op_not(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    U256& a = s.stack[s.stackPointer];
    for (int i = 0; i < 4; ++i) a.limbs[i] = ~a.limbs[i];
    ++s.pc;
    return true;
}

// 0x1a BYTE — the i-th byte of x, counting from the most significant (i = 0).
// i >= 32 yields 0. Stack: i = top, x = second.
bool op_byte(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& i = s.stack[s.stackPointer];
    U256&       x = s.stack[s.stackPointer + 1];
    U256 r{};
    if ((i.limbs[1] | i.limbs[2] | i.limbs[3]) == 0 && i.limbs[0] <= 31) {
        const unsigned idx = static_cast<unsigned>(i.limbs[0]);  // 0 = most significant
        const unsigned pos = 31 - idx;                           // byte index from LSB
        r.limbs[0] = (x.limbs[pos >> 3] >> ((pos & 7) * 8)) & 0xFFULL;
    }
    x = r;
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x1b SHL — value << shift. Stack: shift = top, value = second.
bool op_shl(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& sh = s.stack[s.stackPointer];
    U256&       v  = s.stack[s.stackPointer + 1];
    v = shl(v, shift_amount(sh));
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x1c SHR — logical value >> shift.
bool op_shr(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& sh = s.stack[s.stackPointer];
    U256&       v  = s.stack[s.stackPointer + 1];
    v = shr(v, shift_amount(sh));
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x1d SAR — arithmetic (sign-propagating) value >> shift.
bool op_sar(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& sh = s.stack[s.stackPointer];
    U256&       v  = s.stack[s.stackPointer + 1];
    v = sar(v, shift_amount(sh));
    ++s.stackPointer;
    ++s.pc;
    return true;
}

}  // namespace

void register_bitwise(InstrTable& t) {
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
    t[0x1b] = &op_shl;
    t[0x1c] = &op_shr;
    t[0x1d] = &op_sar;
}

}  // namespace zevm

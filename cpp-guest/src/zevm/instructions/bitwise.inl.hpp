#pragma once
// bitwise.cpp — comparison & bitwise-logic opcodes (0x10..0x1e: LT, GT, SLT,
// SGT, EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR, CLZ).
//
// Endianness (the stack is little-endian; see EvmState::stack):
//   * CLZ — positional; operates on the LE limbs directly (ld_le/st_le identity).
//   * AND/OR/XOR/NOT — bit-parallel, so endianness-agnostic: operate on the slots
//     in place, no conversion.
//   * ISZERO/EQ — zero and equality are the same in either representation: test
//     the slots directly; the 0/1 result is stored via st_le.
//   * LT/GT/SLT/SGT — ordering uses the LE-native u256_lt / u256_sign helpers.
//   * SHL/SHR/SAR, BYTE — the shift amount / byte index is the low byte of the LE
//     slot (low_scalar); a shift by a whole number of bytes is a byte move
//     (memmove + memset) on the LE bytes, and BYTE just copies one byte. Only an
//     off-byte shift amount falls back to the limb path.
// Binary ops take a = top, b = second and push the result into b's slot.

#include "detail.hpp"

#include <cstring>  // std::memmove / std::memset (byte-granular shifts)

namespace zevm {

namespace bitwise_ops {

// The boolean results 0/1 as a little-endian word. Compile-time constants.
inline U256 bool_word(bool v) { return v ? U256{{1, 0, 0, 0}} : U256{}; }

// Signed a < b (two's complement): differing signs decide it (negative < non-
// negative); same sign falls back to the unsigned order (u256_lt).
inline bool slt(const U256& a, const U256& b) {
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

// A small scalar (shift amount / byte index) read off a little-endian slot:
// < 256 iff every byte but the lowest is zero, in which case the value is that
// low byte (limbs[0] & 0xFF). Returns 256 otherwise, which the shift handlers
// treat as out-of-range and BYTE as >= 32.
inline unsigned low_scalar(const U256& v) {
    if ((v.limbs[1] | v.limbs[2] | v.limbs[3] |
         (v.limbs[0] & ~0xFFULL)) != 0)
        return 256;
    return static_cast<unsigned>(v.limbs[0] & 0xFF);
}

// Byte-granular shifts on a little-endian slot in place (k bytes, 1..31). The LE
// byte array runs LSB (byte 0) .. MSB (byte 31), so SHL moves bytes toward byte
// 31 and SHR/SAR toward byte 0; the vacated end is zero-filled (SAR sign-filled).
inline void byte_shl(U256& v, unsigned k) {
    uint8_t* b = reinterpret_cast<uint8_t*>(&v);
    std::memmove(b + k, b, 32 - k);
    std::memset(b, 0, k);
}
inline void byte_shr(U256& v, unsigned k) {
    uint8_t* b = reinterpret_cast<uint8_t*>(&v);
    std::memmove(b, b + k, 32 - k);
    std::memset(b + (32 - k), 0, k);
}
inline void byte_sar(U256& v, unsigned k) {
    uint8_t* b = reinterpret_cast<uint8_t*>(&v);
    const uint8_t fill = (b[31] & 0x80) ? 0xFF : 0x00;  // sign byte (MSB = byte 31)
    std::memmove(b, b + k, 32 - k);
    std::memset(b + (32 - k), fill, k);
}

// 0x10 LT — unsigned a < b.
bool op_lt(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    s.stack[R.sp + 1] =
        bool_word(u256_lt(s.stack[R.sp], s.stack[R.sp + 1]));
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x11 GT — unsigned a > b.
bool op_gt(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    s.stack[R.sp + 1] =
        bool_word(u256_lt(s.stack[R.sp + 1], s.stack[R.sp]));
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x12 SLT — signed a < b.
bool op_slt(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    s.stack[R.sp + 1] =
        bool_word(slt(s.stack[R.sp], s.stack[R.sp + 1]));
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x13 SGT — signed a > b.
bool op_sgt(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    s.stack[R.sp + 1] =
        bool_word(slt(s.stack[R.sp + 1], s.stack[R.sp]));
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x14 EQ — a == b. Equality is representation-agnostic: compare BE slots.
bool op_eq(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const bool e = u256_eq(s.stack[R.sp], s.stack[R.sp + 1]);
    s.stack[R.sp + 1] = bool_word(e);
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x15 ISZERO — a == 0 (unary). Zero is all-zero in either representation; the
// operand is a little-endian slot, so test from its least-significant lane
// (limbs[0]) first and short-circuit — a small nonzero operand (the common case)
// exits on the first lane.
bool op_iszero(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[R.sp];
    const bool z = a.limbs[0] == 0 && a.limbs[1] == 0 && a.limbs[2] == 0 && a.limbs[3] == 0;
    s.stack[R.sp] = bool_word(z);
    ++R.pc;
    return true;
}

// AND/OR/XOR are bit-parallel, so endianness-agnostic — operate on the
// big-endian slots in place (the result is big-endian too). Each is its own
// function with the four limbs unrolled, rather than a shared template.

// 0x16 AND.
bool op_and(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[R.sp];
    U256&       b = s.stack[R.sp + 1];
    b.limbs[0] &= a.limbs[0];
    b.limbs[1] &= a.limbs[1];
    b.limbs[2] &= a.limbs[2];
    b.limbs[3] &= a.limbs[3];
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x17 OR.
bool op_or(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[R.sp];
    U256&       b = s.stack[R.sp + 1];
    b.limbs[0] |= a.limbs[0];
    b.limbs[1] |= a.limbs[1];
    b.limbs[2] |= a.limbs[2];
    b.limbs[3] |= a.limbs[3];
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x18 XOR.
bool op_xor(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& a = s.stack[R.sp];
    U256&       b = s.stack[R.sp + 1];
    b.limbs[0] ^= a.limbs[0];
    b.limbs[1] ^= a.limbs[1];
    b.limbs[2] ^= a.limbs[2];
    b.limbs[3] ^= a.limbs[3];
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x19 NOT — bitwise complement (unary). Bit-parallel: complement the BE slot.
bool op_not(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    U256& a = s.stack[R.sp];
    for (int i = 0; i < 4; ++i) a.limbs[i] = ~a.limbs[i];
    ++R.pc;
    return true;
}

// 0x1e CLZ — count leading zero bits of the 256-bit word (EIP-7939, Osaka).
// clz(0) == 256. Positional; operates on the LE limbs directly (ld_le identity).
bool op_clz(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, R.sp);
    uint64_t n;  // limb[3] is most significant; higher all-zero limbs add 64 each
    if (a.limbs[3] != 0)      n =       static_cast<uint64_t>(__builtin_clzll(a.limbs[3]));
    else if (a.limbs[2] != 0) n =  64 + static_cast<uint64_t>(__builtin_clzll(a.limbs[2]));
    else if (a.limbs[1] != 0) n = 128 + static_cast<uint64_t>(__builtin_clzll(a.limbs[1]));
    else if (a.limbs[0] != 0) n = 192 + static_cast<uint64_t>(__builtin_clzll(a.limbs[0]));
    else                      n = 256;
    st_le(s, R.sp, U256{{n, 0, 0, 0}});
    ++R.pc;
    return true;
}

// 0x1a BYTE — the i-th byte of x, counting from the most significant (i = 0).
// i >= 32 yields 0. Stack: i = top, x = second. In the LE slot the most-
// significant byte (i = 0) is raw byte[31], so byte i of x is raw byte[31 - i].
bool op_byte(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const unsigned idx = low_scalar(s.stack[R.sp]);  // 0 = most significant
    U256 r{};
    if (idx < 32) {
        const uint8_t byte = reinterpret_cast<const uint8_t*>(&s.stack[R.sp + 1])[31 - idx];
        r.limbs[0] = static_cast<uint64_t>(byte);  // result value in the low lane
    }
    s.stack[R.sp + 1] = r;
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x1b SHL — value << shift. Stack: shift = top, value = second.
bool op_shl(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const unsigned n = low_scalar(s.stack[R.sp]);
    U256& v = s.stack[R.sp + 1];
    if (n >= 256)        v = U256{};
    else if (n == 0)     { /* unchanged */ }
    else if (n % 8 == 0) byte_shl(v, n / 8);
    else                 st_le(s, R.sp + 1, shl(ld_le(s, R.sp + 1), n));
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x1c SHR — logical value >> shift.
bool op_shr(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const unsigned n = low_scalar(s.stack[R.sp]);
    U256& v = s.stack[R.sp + 1];
    if (n >= 256)        v = U256{};
    else if (n == 0)     { /* unchanged */ }
    else if (n % 8 == 0) byte_shr(v, n / 8);
    else                 st_le(s, R.sp + 1, shr(ld_le(s, R.sp + 1), n));
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x1d SAR — arithmetic (sign-propagating) value >> shift.
bool op_sar(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const unsigned n = low_scalar(s.stack[R.sp]);
    U256& v = s.stack[R.sp + 1];
    if (n >= 256) {
        // out-of-range: every bit becomes the sign bit (raw byte[31] high bit)
        const uint8_t fill = (reinterpret_cast<const uint8_t*>(&v)[31] & 0x80) ? 0xFF : 0x00;
        std::memset(&v, fill, 32);
    } else if (n == 0)   { /* unchanged */ }
    else if (n % 8 == 0) byte_sar(v, n / 8);
    else                 st_le(s, R.sp + 1, sar(ld_le(s, R.sp + 1), n));
    ++R.sp;
    ++R.pc;
    return true;
}

}  // namespace


}  // namespace zevm

// arith.cpp — arithmetic opcodes (0x01..0x0b: ADD, MUL, SUB, DIV, SDIV, MOD,
// SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND).
//
// The 256-bit heavy lifting routes through the ZisK-accelerated zeg::bi backend:
// add256 (ADD/SUB), arith256 (MUL and EXP's square-and-multiply), arith256_mod
// (ADDMOD/MULMOD), and fcall_bigint_div (DIV/MOD, and the magnitude step of the
// signed variants). All of it works on little-endian limbs, so every consumed
// operand is forced to LE (to_le) first and the result is tagged LE. Sign
// handling, the divide-by-zero guards, and SIGNEXTEND are plain limb work.
// Binary ops take a = top, b = second, push a OP b into b's slot.

#include "detail.hpp"

#include "bigint/backend.hpp"  // zeg::bi::{add256,arith256,arith256_mod,fcall_bigint_div}

namespace zevm {

namespace {

constexpr uint64_t ZERO4[4] = {0, 0, 0, 0};
constexpr uint64_t ONE4[4]  = {1, 0, 0, 0};

// Significant limb count (>= 1), for the variable-length bigint_div fcall.
inline int limbs_len(const uint64_t x[4]) {
    int n = 4;
    while (n > 1 && x[n - 1] == 0) --n;
    return n;
}

// Low 256 bits of a * b (the EVM MUL / the multiply step of EXP).
inline U256 mul_low(const U256& a, const U256& b) {
    uint64_t dl[4], dh[4];
    zeg::bi::arith256(a.limbs, b.limbs, ZERO4, dl, dh);
    return U256{{dl[0], dl[1], dl[2], dl[3]}};
}

// Unsigned q = a / b, r = a % b. Caller guarantees b != 0.
inline void udivmod(const U256& a, const U256& b, U256& q, U256& r) {
    uint64_t quo[8] = {0}, rem[8] = {0};
    int lq = 0, lr = 0;
    zeg::bi::fcall_bigint_div(a.limbs, limbs_len(a.limbs),
                              b.limbs, limbs_len(b.limbs),
                              quo, &lq, rem, &lr);
    for (int i = 0; i < 4; ++i) { q.limbs[i] = quo[i]; r.limbs[i] = rem[i]; }
}

// 0x01 ADD — pop a and b, push (a + b) mod 2^256.
bool op_add(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    zeg::bi::add256(a.limbs, b.limbs, /*cin=*/0, b.limbs);  // b = a + b (mod 2^256)
    s.stackBE[s.stackPointer + 1] = kLE;
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x02 MUL — push (a * b) mod 2^256.
bool op_mul(EvmState& s) {
    if (s.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_LOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    b = mul_low(a, b);
    s.stackBE[s.stackPointer + 1] = kLE;
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x03 SUB — push (a - b) mod 2^256, where a is the top item.
bool op_sub(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    // a - b == a + ~b + 1 (two's complement), via the accelerated adder.
    const uint64_t nb[4] = {~b.limbs[0], ~b.limbs[1], ~b.limbs[2], ~b.limbs[3]};
    zeg::bi::add256(a.limbs, nb, /*cin=*/1, b.limbs);
    s.stackBE[s.stackPointer + 1] = kLE;
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x04 DIV — unsigned a / b (0 when b == 0).
bool op_div(EvmState& s) {
    if (s.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_LOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    if (u256_is_zero(b)) {
        b = U256{};
    } else {
        U256 q, r; udivmod(a, b, q, r); b = q;
    }
    s.stackBE[s.stackPointer + 1] = kLE;
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x05 SDIV — signed a / b, truncated toward zero (0 when b == 0).
bool op_sdiv(EvmState& s) {
    if (s.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_LOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    if (u256_is_zero(b)) {
        b = U256{};
    } else {
        const bool na = u256_sign(a), nb = u256_sign(b);
        // Overflow case: (-2^255) / -1 = -2^255 (result stays a).
        const bool a_is_min = a.limbs[0] == 0 && a.limbs[1] == 0 &&
                              a.limbs[2] == 0 && a.limbs[3] == 0x8000000000000000ULL;
        const bool b_is_neg1 = b.limbs[0] == ~0ULL && b.limbs[1] == ~0ULL &&
                               b.limbs[2] == ~0ULL && b.limbs[3] == ~0ULL;
        if (a_is_min && b_is_neg1) {
            b = a;  // result is -2^255 (== a); write it into the result slot
        } else {
            const U256 ua = na ? u256_neg(a) : a;
            const U256 ub = nb ? u256_neg(b) : b;
            U256 q, r; udivmod(ua, ub, q, r);
            b = (na != nb) ? u256_neg(q) : q;
        }
    }
    s.stackBE[s.stackPointer + 1] = kLE;
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x06 MOD — unsigned a % b (0 when b == 0).
bool op_mod(EvmState& s) {
    if (s.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_LOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    if (u256_is_zero(b)) {
        b = U256{};
    } else {
        U256 q, r; udivmod(a, b, q, r); b = r;
    }
    s.stackBE[s.stackPointer + 1] = kLE;
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x07 SMOD — signed a % b, result takes the sign of a (0 when b == 0).
bool op_smod(EvmState& s) {
    if (s.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_LOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    if (u256_is_zero(b)) {
        b = U256{};
    } else {
        const bool na = u256_sign(a);
        const U256 ua = na ? u256_neg(a) : a;
        const U256 ub = u256_sign(b) ? u256_neg(b) : b;
        U256 q, r; udivmod(ua, ub, q, r);
        b = na ? u256_neg(r) : r;
    }
    s.stackBE[s.stackPointer + 1] = kLE;
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x08 ADDMOD — (a + b) mod m (0 when m == 0). Ternary: a, b, m.
bool op_addmod(EvmState& s) {
    if (s.gas < GAS_MID) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_MID;
    if (stack_depth(s) < 3) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    to_le(s, s.stackPointer + 2);
    const U256& a = s.stack[s.stackPointer];
    const U256& b = s.stack[s.stackPointer + 1];
    U256&       m = s.stack[s.stackPointer + 2];
    if (u256_is_zero(m)) {
        m = U256{};
    } else {
        // (a*1 + b) mod m; the 512-bit product accommodates the a+b overflow.
        uint64_t d[4];
        zeg::bi::arith256_mod(a.limbs, ONE4, b.limbs, m.limbs, d);
        m = U256{{d[0], d[1], d[2], d[3]}};
    }
    s.stackBE[s.stackPointer + 2] = kLE;
    s.stackPointer += 2;
    ++s.pc;
    return true;
}

// 0x09 MULMOD — (a * b) mod m (0 when m == 0). Ternary: a, b, m.
bool op_mulmod(EvmState& s) {
    if (s.gas < GAS_MID) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_MID;
    if (stack_depth(s) < 3) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    to_le(s, s.stackPointer + 2);
    const U256& a = s.stack[s.stackPointer];
    const U256& b = s.stack[s.stackPointer + 1];
    U256&       m = s.stack[s.stackPointer + 2];
    if (u256_is_zero(m)) {
        m = U256{};
    } else {
        uint64_t d[4];
        zeg::bi::arith256_mod(a.limbs, b.limbs, ZERO4, m.limbs, d);
        m = U256{{d[0], d[1], d[2], d[3]}};
    }
    s.stackBE[s.stackPointer + 2] = kLE;
    s.stackPointer += 2;
    ++s.pc;
    return true;
}

// 0x0a EXP — a ** b mod 2^256. Gas is dynamic: 10 + 50 per byte of exponent.
bool op_exp(EvmState& s) {
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    const U256& base = s.stack[s.stackPointer];
    U256&       exp  = s.stack[s.stackPointer + 1];

    int top = -1;  // highest set bit of the exponent
    for (int i = 255; i >= 0; --i)
        if ((exp.limbs[i >> 6] >> (i & 63)) & 1ULL) { top = i; break; }
    const int64_t byte_len = top < 0 ? 0 : (top / 8 + 1);
    const int64_t cost = GAS_EXP + GAS_EXPBYTE * byte_len;
    if (s.gas < cost) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= cost;

    // Square-and-multiply, MSB -> LSB (skips the exponent's leading zero bits).
    U256 result{{1, 0, 0, 0}};
    for (int i = top; i >= 0; --i) {
        result = mul_low(result, result);
        if ((exp.limbs[i >> 6] >> (i & 63)) & 1ULL) result = mul_low(result, base);
    }
    exp = result;
    s.stackBE[s.stackPointer + 1] = kLE;
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x0b SIGNEXTEND — sign-extend x from the byte at index i (0 = least
// significant byte). i >= 31 leaves x unchanged. Stack: i = top, x = second.
bool op_signextend(EvmState& s) {
    if (s.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_LOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    const U256& i = s.stack[s.stackPointer];
    U256&       x = s.stack[s.stackPointer + 1];

    const bool in_range = (i.limbs[1] | i.limbs[2] | i.limbs[3]) == 0 && i.limbs[0] <= 30;
    if (in_range) {
        const unsigned bit  = static_cast<unsigned>(i.limbs[0]) * 8 + 7;  // sign bit
        const unsigned limb = bit >> 6, off = bit & 63;
        const bool sign = (x.limbs[limb] >> off) & 1ULL;
        // Bits [0..bit] within `limb` are kept; everything above is set to `sign`.
        const uint64_t low_mask = (off == 63) ? ~0ULL : ((1ULL << (off + 1)) - 1);
        if (sign) {
            x.limbs[limb] |= ~low_mask;
            for (unsigned l = limb + 1; l < 4; ++l) x.limbs[l] = ~0ULL;
        } else {
            x.limbs[limb] &= low_mask;
            for (unsigned l = limb + 1; l < 4; ++l) x.limbs[l] = 0;
        }
    }
    s.stackBE[s.stackPointer + 1] = kLE;
    ++s.stackPointer;
    ++s.pc;
    return true;
}

}  // namespace

void register_arith(InstrTable& t) {
    t[0x01] = &op_add;
    t[0x02] = &op_mul;
    t[0x03] = &op_sub;
    t[0x04] = &op_div;
    t[0x05] = &op_sdiv;
    t[0x06] = &op_mod;
    t[0x07] = &op_smod;
    t[0x08] = &op_addmod;
    t[0x09] = &op_mulmod;
    t[0x0a] = &op_exp;
    t[0x0b] = &op_signextend;
}

}  // namespace zevm

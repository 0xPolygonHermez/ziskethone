#pragma once
// arith.cpp — arithmetic opcodes (0x01..0x0b: ADD, MUL, SUB, DIV, SDIV, MOD,
// SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND).
//
// The 256-bit heavy lifting routes through the ZisK-accelerated zeg::bi backend:
// add256 (ADD/SUB), arith256 (MUL and EXP's square-and-multiply), arith256_mod
// (ADDMOD/MULMOD), and fcall_bigint_div (DIV/MOD, and the magnitude step of the
// signed variants). All of it works on little-endian limbs — and the stack now
// stores little-endian integers, so ld_le/st_le are identity and the operands
// feed straight in with no byteswap. Sign handling, the divide-by-zero guards,
// and SIGNEXTEND are plain limb work. Binary ops take a = top, b = second, push
// a OP b into b's slot.

#include "detail.hpp"

#include "bigint/backend.hpp"  // zeg::bi::{add256,arith256,arith256_mod,fcall_bigint_div}

namespace zevm {

namespace arith_ops {

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
//
// Fast path: when either operand is < 2^64 (its three high limbs are zero — the
// overwhelmingly common case: counters, offsets, pointer bumps), the add runs in
// the low 64-bit lane and the large operand's high lanes pass through verbatim —
// no add256 precompile. A carry past bit 64 cascades one lane at a time; carry
// off the top lane drops (mod 2^256). Only the both-large case takes add256.
bool op_add(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& sa = s.stack[R.sp];      // a, LE slot (distinct from sb)
    U256&       sb = s.stack[R.sp + 1];  // b / result, LE slot

    if ((sa.limbs[1] | sa.limbs[2] | sa.limbs[3]) == 0) {  // a < 2^64 (covers both-small)
        if (sa.limbs[0] != 0) {                            // a == 0 -> result is b, in place
            const uint64_t t = sb.limbs[0];
            const uint64_t r = t + sa.limbs[0];
            sb.limbs[0] = r;
            bool carry = r < t;
            for (int i = 1; carry && i < 4; ++i) {         // b's high lanes already in place
                sb.limbs[i] += 1;
                carry = (sb.limbs[i] == 0);
            }
        }
    } else if ((sb.limbs[1] | sb.limbs[2] | sb.limbs[3]) == 0) {  // b < 2^64, a large
        if (sb.limbs[0] == 0) {
            sb = sa;                                       // x + 0: raw slot copy
        } else {
            const uint64_t t = sa.limbs[0];
            const uint64_t r = t + sb.limbs[0];
            sb.limbs[0] = r;
            bool carry = r < t;
            for (int i = 1; i < 4; ++i) {                  // no break: fill the slot from a
                if (carry) {
                    sb.limbs[i] = sa.limbs[i] + 1;
                    carry = (sb.limbs[i] == 0);
                } else {
                    sb.limbs[i] = sa.limbs[i];             // verbatim copy
                }
            }
        }
    } else {                                               // both >= 2^64: full path
        const U256 a = ld_le(s, R.sp);
        U256       b = ld_le(s, R.sp + 1);
        zeg::bi::add256(a.limbs, b.limbs, /*cin=*/0, b.limbs);  // b = a + b (mod 2^256)
        st_le(s, R.sp + 1, b);
    }
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x02 MUL — push (a * b) mod 2^256.
bool op_mul(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, R.sp);
    U256       b = ld_le(s, R.sp + 1);
    b = mul_low(a, b);
    st_le(s, R.sp + 1, b);
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x03 SUB — push (a - b) mod 2^256, where a is the top item.
//
// Fast path: when the subtrahend b is < 2^64 (the common `x - small_const`,
// and any both-small case including the deliberate-underflow ones), the
// subtract runs in the low 64-bit lane and a's high lanes are copied through
// verbatim unless a borrow cascades (an all-zero lane of a turns all-0xFF and
// the borrow continues — which builds the correct wrapped result for a < b).
// Only b >= 2^64 (including small-minus-large) takes the full path.
bool op_sub(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& sa = s.stack[R.sp];      // a, minuend (distinct from sb)
    U256&       sb = s.stack[R.sp + 1];  // b, subtrahend / result

    if ((sb.limbs[1] | sb.limbs[2] | sb.limbs[3]) == 0) {  // b < 2^64
        if (sb.limbs[0] == 0) {
            sb = sa;                                       // a - 0: raw slot copy
        } else {
            const uint64_t bv = sb.limbs[0];
            const uint64_t t  = sa.limbs[0];
            sb.limbs[0] = t - bv;
            bool borrow = t < bv;
            for (int i = 1; i < 4; ++i) {                  // no break: fill the slot from a
                if (borrow) {
                    sb.limbs[i] = sa.limbs[i] - 1;         // a-lane 0 -> all-FF, borrow continues
                    borrow = (sa.limbs[i] == 0);
                } else {
                    sb.limbs[i] = sa.limbs[i];             // verbatim copy
                }
            }
        }
    } else {                                               // b >= 2^64: full LE path
        const U256 a = ld_le(s, R.sp);
        U256       b = ld_le(s, R.sp + 1);
        // a - b == a + ~b + 1 (two's complement), via the accelerated adder.
        const uint64_t nb[4] = {~b.limbs[0], ~b.limbs[1], ~b.limbs[2], ~b.limbs[3]};
        zeg::bi::add256(a.limbs, nb, /*cin=*/1, b.limbs);
        st_le(s, R.sp + 1, b);
    }
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x04 DIV — unsigned a / b (0 when b == 0).
bool op_div(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, R.sp);
    U256       b = ld_le(s, R.sp + 1);
    if (u256_is_zero(b)) {
        b = U256{};
    } else {
        U256 q, r; udivmod(a, b, q, r); b = q;
    }
    st_le(s, R.sp + 1, b);
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x05 SDIV — signed a / b, truncated toward zero (0 when b == 0).
bool op_sdiv(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, R.sp);
    U256       b = ld_le(s, R.sp + 1);
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
    st_le(s, R.sp + 1, b);
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x06 MOD — unsigned a % b (0 when b == 0).
bool op_mod(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, R.sp);
    U256       b = ld_le(s, R.sp + 1);
    if (u256_is_zero(b)) {
        b = U256{};
    } else {
        U256 q, r; udivmod(a, b, q, r); b = r;
    }
    st_le(s, R.sp + 1, b);
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x07 SMOD — signed a % b, result takes the sign of a (0 when b == 0).
bool op_smod(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, R.sp);
    U256       b = ld_le(s, R.sp + 1);
    if (u256_is_zero(b)) {
        b = U256{};
    } else {
        const bool na = u256_sign(a);
        const U256 ua = na ? u256_neg(a) : a;
        const U256 ub = u256_sign(b) ? u256_neg(b) : b;
        U256 q, r; udivmod(ua, ub, q, r);
        b = na ? u256_neg(r) : r;
    }
    st_le(s, R.sp + 1, b);
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x08 ADDMOD — (a + b) mod m (0 when m == 0). Ternary: a, b, m.
bool op_addmod(EvmState& s, Regs& R) {
    if (R.gas < GAS_MID) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_MID;
    if (stack_depth(R.sp) < 3) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, R.sp);
    const U256 b = ld_le(s, R.sp + 1);
    U256       m = ld_le(s, R.sp + 2);
    if (u256_is_zero(m)) {
        m = U256{};
    } else {
        // (a*1 + b) mod m; the 512-bit product accommodates the a+b overflow.
        uint64_t d[4];
        zeg::bi::arith256_mod(a.limbs, ONE4, b.limbs, m.limbs, d);
        m = U256{{d[0], d[1], d[2], d[3]}};
    }
    st_le(s, R.sp + 2, m);
    R.sp += 2;
    ++R.pc;
    return true;
}

// 0x09 MULMOD — (a * b) mod m (0 when m == 0). Ternary: a, b, m.
bool op_mulmod(EvmState& s, Regs& R) {
    if (R.gas < GAS_MID) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_MID;
    if (stack_depth(R.sp) < 3) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 a = ld_le(s, R.sp);
    const U256 b = ld_le(s, R.sp + 1);
    U256       m = ld_le(s, R.sp + 2);
    if (u256_is_zero(m)) {
        m = U256{};
    } else {
        uint64_t d[4];
        zeg::bi::arith256_mod(a.limbs, b.limbs, ZERO4, m.limbs, d);
        m = U256{{d[0], d[1], d[2], d[3]}};
    }
    st_le(s, R.sp + 2, m);
    R.sp += 2;
    ++R.pc;
    return true;
}

// 0x0a EXP — a ** b mod 2^256. Gas is dynamic: 10 + 50 per byte of exponent.
//
// The exponent is read straight off its little-endian slot — only its bit
// pattern matters. Its lanes run least-significant first (e.limbs[0] is the low
// 8 bytes); the highest set bit is found by the first non-zero lane from the top
// (limbs[3]) plus a clz on it — no 256-iteration scan. The square-and-multiply
// then walks the bits top..0 lane by lane, skipping the leading all-zero lanes.
bool op_exp(EvmState& s, Regs& R) {
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256  base = ld_le(s, R.sp);
    const U256& e    = s.stack[R.sp + 1];  // exponent, little-endian slot

    // Highest set bit: first non-zero lane (MS first) + clz on it.
    int top = -1;
    for (int k = 3; k >= 0; --k)
        if (e.limbs[k] != 0) {
            top = k * 64 + (63 - __builtin_clzll(e.limbs[k]));
            break;
        }
    const int64_t byte_len = top < 0 ? 0 : (top / 8 + 1);
    const int64_t cost = GAS_EXP + GAS_EXPBYTE * byte_len;
    if (R.gas < cost) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= cost;

    // Square-and-multiply, MSB -> LSB, lane by lane (lane vl == e.limbs[vl]).
    // top < 0 (exponent 0) runs zero iterations -> 1.
    U256 result{{1, 0, 0, 0}};
    const int topLane = top >> 6;
    for (int vl = topLane; vl >= 0; --vl) {
        const uint64_t lane = e.limbs[vl];
        for (int b = (vl == topLane ? (top & 63) : 63); b >= 0; --b) {
            result = mul_low(result, result);
            if ((lane >> b) & 1ULL) result = mul_low(result, base);
        }
    }
    st_le(s, R.sp + 1, result);
    ++R.sp;
    ++R.pc;
    return true;
}

// 0x0b SIGNEXTEND — sign-extend x from the byte at index i (0 = least
// significant byte). i >= 31 leaves x unchanged. Stack: i = top, x = second.
bool op_signextend(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 i = ld_le(s, R.sp);
    U256       x = ld_le(s, R.sp + 1);

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
    st_le(s, R.sp + 1, x);
    ++R.sp;
    ++R.pc;
    return true;
}

}  // namespace


}  // namespace zevm

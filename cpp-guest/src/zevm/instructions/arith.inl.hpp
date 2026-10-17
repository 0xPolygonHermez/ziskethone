#pragma once
// arith.cpp — arithmetic opcodes (0x01..0x0b: ADD, MUL, SUB, DIV, SDIV, MOD,
// SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND).
//
// On ZisK the 256-bit heavy lifting goes through the little-endian U256 ABI
// (zkvm_u256_le.h): add/sub (the full-width ADD/SUB paths), mul, the division
// family (DIV/SDIV/MOD/SMOD, with a checked division), addmod/mulmod and exp. On
// the host the same opcodes run on the portable software in bigint/backend.hpp.
// All of it works on little-endian limbs — and the stack stores little-endian
// integers, so ld_le/st_le are identity and the operands feed straight in with no
// byteswap. Binary ops take a = top, b = second, push a OP b into b's slot.

#include "detail.hpp"

#if defined(ZEG_ZISK)
#include "zkvm_u256_le.h"  // ZisK's little-endian U256 ABI
#else
#include "bigint/backend.hpp"  // zeg::bi::{add256,arith256,arith256_mod,fcall_bigint_div}
#endif

namespace zevm {

namespace arith_ops {

#if defined(ZEG_ZISK)
// U256 is `uint64_t limbs[4]`, least significant first: exactly zkvm_u256_le.
inline const zkvm_u256_le* le(const U256& x) { return reinterpret_cast<const zkvm_u256_le*>(&x); }
inline zkvm_u256_le* le(U256& x) { return reinterpret_cast<zkvm_u256_le*>(&x); }

// The inline zkvmcalls (add, sub, mul, addmod, mulmod) are asm statements with a
// register per argument. Expanded inside zevm's dispatch loop they make GCC spill
// registers across the whole loop (+4% cost on a mainnet block, all stack loads and
// stores), so each runs out of line: the loop keeps only a call, and the cheap
// small-operand paths of ADD and SUB stay inline. (div, mod, exp and the signed
// division are calls anyway.) Each writes its result into the last stack slot named.
[[gnu::noinline]] inline void abi_add(U256* top) { zkvm_u256_le_add(le(top[0]), le(top[1]), le(top[1])); }
[[gnu::noinline]] inline void abi_sub(U256* top) { zkvm_u256_le_sub(le(top[0]), le(top[1]), le(top[1])); }
[[gnu::noinline]] inline void abi_mul(U256* top) { zkvm_u256_le_mul(le(top[0]), le(top[1]), le(top[1])); }
[[gnu::noinline]] inline void abi_addmod(U256* top) {
    zkvm_u256_le_addmod(le(top[0]), le(top[1]), le(top[2]), le(top[2]));
}
[[gnu::noinline]] inline void abi_mulmod(U256* top) {
    zkvm_u256_le_mulmod(le(top[0]), le(top[1]), le(top[2]), le(top[2]));
}
#else
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
#endif

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
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& sa = R.top[0];      // a, LE slot (distinct from sb)
    U256&       sb = R.top[1];  // b / result, LE slot

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
#if defined(ZEG_ZISK)
        abi_add(R.top);  // b = a + b (mod 2^256)
#else
        const U256 a = ld_le(R.top);
        U256       b = ld_le(R.top + 1);
        zeg::bi::add256(a.limbs, b.limbs, /*cin=*/0, b.limbs);  // b = a + b (mod 2^256)
        st_le(R.top + 1, b);
#endif
    }
    return true;
}

// 0x02 MUL — push (a * b) mod 2^256.
bool op_mul(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
#if defined(ZEG_ZISK)
    abi_mul(R.top);
#else
    const U256 a = ld_le(R.top);
    U256       b = ld_le(R.top + 1);
    b = mul_low(a, b);
    st_le(R.top + 1, b);
#endif
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
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256& sa = R.top[0];      // a, minuend (distinct from sb)
    U256&       sb = R.top[1];  // b, subtrahend / result

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
#if defined(ZEG_ZISK)
        abi_sub(R.top);  // b = a - b (mod 2^256)
#else
        const U256 a = ld_le(R.top);
        U256       b = ld_le(R.top + 1);
        // a - b == a + ~b + 1 (two's complement).
        const uint64_t nb[4] = {~b.limbs[0], ~b.limbs[1], ~b.limbs[2], ~b.limbs[3]};
        zeg::bi::add256(a.limbs, nb, /*cin=*/1, b.limbs);
        st_le(R.top + 1, b);
#endif
    }
    return true;
}

// 0x04 DIV — unsigned a / b (0 when b == 0).
bool op_div(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
#if defined(ZEG_ZISK)
    zkvm_u256_le_div(le(R.top[0]), le(R.top[1]), le(R.top[1]));  // 0 when b == 0
#else
    const U256 a = ld_le(R.top);
    U256       b = ld_le(R.top + 1);
    if (u256_is_zero(b)) {
        b = U256{};
    } else {
        U256 q, r; udivmod(a, b, q, r); b = q;
    }
    st_le(R.top + 1, b);
#endif
    return true;
}

// 0x05 SDIV — signed a / b, truncated toward zero (0 when b == 0).
bool op_sdiv(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
#if defined(ZEG_ZISK)
    zkvm_u256_le_sdiv(le(R.top[0]), le(R.top[1]), le(R.top[1]));  // 0 when b == 0
#else
    const U256 a = ld_le(R.top);
    U256       b = ld_le(R.top + 1);
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
    st_le(R.top + 1, b);
#endif
    return true;
}

// 0x06 MOD — unsigned a % b (0 when b == 0).
bool op_mod(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
#if defined(ZEG_ZISK)
    zkvm_u256_le_mod(le(R.top[0]), le(R.top[1]), le(R.top[1]));  // 0 when b == 0
#else
    const U256 a = ld_le(R.top);
    U256       b = ld_le(R.top + 1);
    if (u256_is_zero(b)) {
        b = U256{};
    } else {
        U256 q, r; udivmod(a, b, q, r); b = r;
    }
    st_le(R.top + 1, b);
#endif
    return true;
}

// 0x07 SMOD — signed a % b, result takes the sign of a (0 when b == 0).
bool op_smod(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
#if defined(ZEG_ZISK)
    zkvm_u256_le_smod(le(R.top[0]), le(R.top[1]), le(R.top[1]));  // 0 when b == 0
#else
    const U256 a = ld_le(R.top);
    U256       b = ld_le(R.top + 1);
    if (u256_is_zero(b)) {
        b = U256{};
    } else {
        const bool na = u256_sign(a);
        const U256 ua = na ? u256_neg(a) : a;
        const U256 ub = u256_sign(b) ? u256_neg(b) : b;
        U256 q, r; udivmod(ua, ub, q, r);
        b = na ? u256_neg(r) : r;
    }
    st_le(R.top + 1, b);
#endif
    return true;
}

// 0x08 ADDMOD — (a + b) mod m (0 when m == 0). Ternary: a, b, m.
bool op_addmod(EvmState& s, Regs& R) {
    if (R.gas < GAS_MID) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_MID;
    if (depth_lt(R, 3)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
#if defined(ZEG_ZISK)
    abi_addmod(R.top);  // 0 when m == 0
#else
    const U256 a = ld_le(R.top);
    const U256 b = ld_le(R.top + 1);
    U256       m = ld_le(R.top + 2);
    if (u256_is_zero(m)) {
        m = U256{};
    } else {
        // (a*1 + b) mod m; the 512-bit product accommodates the a+b overflow.
        uint64_t d[4];
        zeg::bi::arith256_mod(a.limbs, ONE4, b.limbs, m.limbs, d);
        m = U256{{d[0], d[1], d[2], d[3]}};
    }
    st_le(R.top + 2, m);
#endif
    return true;
}

// 0x09 MULMOD — (a * b) mod m (0 when m == 0). Ternary: a, b, m.
bool op_mulmod(EvmState& s, Regs& R) {
    if (R.gas < GAS_MID) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_MID;
    if (depth_lt(R, 3)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
#if defined(ZEG_ZISK)
    abi_mulmod(R.top);  // 0 when m == 0
#else
    const U256 a = ld_le(R.top);
    const U256 b = ld_le(R.top + 1);
    U256       m = ld_le(R.top + 2);
    if (u256_is_zero(m)) {
        m = U256{};
    } else {
        uint64_t d[4];
        zeg::bi::arith256_mod(a.limbs, b.limbs, ZERO4, m.limbs, d);
        m = U256{{d[0], d[1], d[2], d[3]}};
    }
    st_le(R.top + 2, m);
#endif
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
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    [[maybe_unused]] const U256 base = ld_le(R.top);  // the host's square-and-multiply
    const U256& e    = R.top[1];  // exponent, little-endian slot

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

#if defined(ZEG_ZISK)
    zkvm_u256_le_exp(le(R.top[0]), le(R.top[1]), le(R.top[1]));
#else
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
    st_le(R.top + 1, result);
#endif
    return true;
}

// 0x0b SIGNEXTEND — sign-extend x from the byte at index i (0 = least
// significant byte). i >= 31 leaves x unchanged. Stack: i = top, x = second.
bool op_signextend(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 i = ld_le(R.top);
    U256       x = ld_le(R.top + 1);

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
    st_le(R.top + 1, x);
    return true;
}

}  // namespace


}  // namespace zevm

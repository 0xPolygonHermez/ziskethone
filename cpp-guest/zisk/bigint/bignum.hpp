// bignum.hpp — M2 of the MODEXP port: arbitrary-precision arithmetic.
//
// Big numbers are flat little-endian u64 arrays grouped into 256-bit words
// (1 word = 4 u64), with lengths counted in WORDS — mirroring zisklib's
// `&[U256]`. Built on backend.hpp (arith256 / add256 precompiles + bigint_div
// hint). Backend-agnostic. This file: the "short" path (single-word divisor),
// used by modexp_short; the "long" path is added alongside. Faithful to
// zisklib/lib/bigint/{mul,square,add,rem}_short.rs.

#pragma once

#include "backend.hpp"

namespace zeg::bi {

// ---- 256-bit word helpers (operate on one 4-limb word) --------------------
inline bool is_zero4(const uint64_t* x) { return !x[0] && !x[1] && !x[2] && !x[3]; }
inline bool is_one4 (const uint64_t* x) { return x[0]==1 && !x[1] && !x[2] && !x[3]; }
inline bool eq4(const uint64_t* a, const uint64_t* b) { return a[0]==b[0]&&a[1]==b[1]&&a[2]==b[2]&&a[3]==b[3]; }
inline bool lt4(const uint64_t* a, const uint64_t* b) {
    for (int i = 3; i >= 0; --i) if (a[i] != b[i]) return a[i] < b[i];
    return false;
}
inline void cp4(uint64_t* d, const uint64_t* s) { d[0]=s[0]; d[1]=s[1]; d[2]=s[2]; d[3]=s[3]; }
inline bool eq_words(const uint64_t* a, const uint64_t* b, int nwords) {
    for (int i = 0; i < nwords*4; ++i) if (a[i] != b[i]) return false; return true;
}
inline void fail() { for (;;) {} }  // unreachable: a hint/invariant was violated

inline constexpr int MAXW = 70;  // max U256 words for short-path scratch

// ---- multiplication by a single word --------------------------------------
// out = a(len_a words) * b(1 word). Returns out length in words.
inline int mul_short(const uint64_t* a, int len_a, const uint64_t* b, uint64_t* out) {
    uint64_t carry[4] = {0,0,0,0};
    for (int i = 0; i < len_a; ++i) {
        uint64_t cin[4]; cp4(cin, carry);
        arith256(a + 4*i, b, cin, out + 4*i, carry);   // a[i]*b + carry = carry|out[i]
    }
    if (is_zero4(carry)) return len_a;
    cp4(out + 4*len_a, carry); return len_a + 1;
}
// out[8] = a(1 word) * b(1 word). Returns 1 or 2 words.
inline int mul_short_one_limb(const uint64_t* a, const uint64_t* b, uint64_t out[8]) {
    uint64_t zero[4] = {0,0,0,0}, dh[4];
    arith256(a, b, zero, out, dh);
    if (is_zero4(dh)) return 1;
    cp4(out + 4, dh); return 2;
}
inline int square_short(const uint64_t* a, uint64_t out[8]) { return mul_short_one_limb(a, a, out); }

// ---- addition of a single word --------------------------------------------
// out = a(len_a words) + b(1 word). Returns out length in words.
inline int add_short(const uint64_t* a, int len_a, const uint64_t* b, uint64_t* out) {
    uint64_t carry = add256(a, b, 0, out);
    for (int i = 1; i < len_a; ++i) {
        if (carry) { uint64_t z[4] = {0,0,0,0}; carry = add256(a + 4*i, z, 1, out + 4*i); }
        else cp4(out + 4*i, a + 4*i);
    }
    if (!carry) return len_a;
    uint64_t one[4] = {1,0,0,0}; cp4(out + 4*len_a, one); return len_a + 1;
}

// ---- remainder by a single word (hint + verify) ---------------------------
// Verify a == quo·b + rem, with rem < b (or rem==0 ⇒ a==quo·b).
inline void verify_division_short(const uint64_t* a, int len_a, const uint64_t* b,
                                  const uint64_t* quo, int len_quo, const uint64_t* rem) {
    if (!(len_quo > 0 && len_quo <= len_a && !is_zero4(quo + 4*(len_quo-1)))) fail();
    uint64_t q_b[(MAXW+1)*4];
    int q_b_len = mul_short(quo, len_quo, b, q_b);
    if (is_zero4(rem)) {
        if (!(q_b_len == len_a && eq_words(a, q_b, len_a))) fail();
    } else {
        if (!lt4(rem, b)) fail();
        uint64_t q_b_r[(MAXW+1)*4];
        int l = add_short(q_b, q_b_len, rem, q_b_r);
        if (!(l == len_a && eq_words(a, q_b_r, len_a))) fail();
    }
}
// rem = a(len_a words) mod b(1 word).
inline void rem_short(const uint64_t* a, int len_a, const uint64_t* b, uint64_t rem[4]) {
    if (len_a == 1) {
        if (is_zero4(a) || lt4(a, b)) { cp4(rem, a); return; }
        if (eq4(a, b)) { rem[0]=rem[1]=rem[2]=rem[3]=0; return; }
    }
    uint64_t quo[MAXW*4]; uint64_t r4[4]; int lq_u64, lr_u64;
    fcall_bigint_div(a, len_a*4, b, 4, quo, &lq_u64, r4, &lr_u64);
    cp4(rem, r4);
    verify_division_short(a, len_a, b, quo, lq_u64/4, rem);
}

// ---- combined multiply/square + reduce (modulus = 1 word) ------------------
inline void mul_and_reduce_short(const uint64_t a[4], const uint64_t b[4], const uint64_t m[4], uint64_t r[4]) {
    uint64_t out[8]; int len = mul_short_one_limb(a, b, out);
    rem_short(out, len, m, r);
}
inline void square_and_reduce_short(const uint64_t a[4], const uint64_t m[4], uint64_t r[4]) {
    uint64_t out[8]; int len = square_short(a, out);
    rem_short(out, len, m, r);
}

} // namespace zeg::bi

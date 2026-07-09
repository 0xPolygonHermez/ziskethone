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

// ---- combined multiply + reduce (modulus = 1 word) -------------------------
// r = (a * b) mod m for single-word operands, via the arith256_mod precompile
// (d = a*b + c mod m, c = 0). Inputs need not be canonical; the result is always
// reduced. Cheaper than the multiply + hint-verified division it replaced.
inline void mulmod_short(const uint64_t a[4], const uint64_t b[4], const uint64_t m[4], uint64_t r[4]) {
    uint64_t zero[4] = {0,0,0,0};
    arith256_mod(a, b, zero, m, r);
}

// ===========================================================================
// Long path (multi-word divisor / operands). Used by modexp_long.
// ===========================================================================
inline int cmp_words(const uint64_t* a, int la, const uint64_t* b, int lb) {
    if (la != lb) return la < lb ? -1 : 1;
    for (int i = la-1; i >= 0; --i) {
        if (lt4(a+4*i, b+4*i)) return -1;
        if (lt4(b+4*i, a+4*i)) return 1;
    }
    return 0;
}

// out = a(la words) * b(lb words), lb >= 2 (use mul_short for lb==1). Faithful
// schoolbook with carry propagation. Returns out length in words.
inline int mul_long(const uint64_t* a, int la, const uint64_t* b, int lb, uint64_t* out) {
    uint64_t zero[4] = {0,0,0,0}, dh[4];
    arith256(a + 0, b + 0, zero, out + 0, dh);            // out[0], out[1]=hi
    cp4(out + 4*1, dh);
    for (int j = 1; j < lb; ++j) {                        // first row
        uint64_t outj[4]; cp4(outj, out + 4*j);
        arith256(a + 0, b + 4*j, outj, out + 4*j, dh);
        cp4(out + 4*(j+1), dh);
    }
    const int last = lb - 1;
    for (int i = 1; i < la; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < last; ++j) {
            int k = i + j;
            uint64_t outk[4]; cp4(outk, out + 4*k);
            uint64_t dl[4], dh2[4]; arith256(a + 4*i, b + 4*j, outk, dl, dh2);
            cp4(out + 4*k, dl);
            uint64_t outk1[4]; cp4(outk1, out + 4*(k+1));
            carry = add256(outk1, dh2, carry, out + 4*(k+1));
        }
        int k = i + last;
        uint64_t outk[4]; cp4(outk, out + 4*k); uint64_t dh3[4];
        arith256(a + 4*i, b + 4*last, outk, out + 4*k, dh3);
        if (carry == 1) { uint64_t z[4]={0,0,0,0}, tmp[4]; cp4(tmp, dh3); add256(tmp, z, 1, dh3); }
        cp4(out + 4*(i + lb), dh3);
    }
    return is_zero4(out + 4*(la + lb - 1)) ? (la + lb - 1) : (la + lb);
}

// out = a(la words) + b(lb words), la >= lb. Returns out length in words.
inline int add_agtb(const uint64_t* a, int la, const uint64_t* b, int lb, uint64_t* out) {
    uint64_t carry = add256(a + 0, b + 0, 0, out + 0);
    for (int i = 1; i < lb; ++i) carry = add256(a + 4*i, b + 4*i, carry, out + 4*i);
    for (int i = lb; i < la; ++i) {
        if (carry) { uint64_t z[4]={0,0,0,0}; carry = add256(a + 4*i, z, 1, out + 4*i); }
        else cp4(out + 4*i, a + 4*i);
    }
    if (!carry) return la;
    uint64_t one[4]={1,0,0,0}; cp4(out + 4*la, one); return la + 1;
}

// Verify a == quo·b + rem (multi-word).
inline void verify_division_long(const uint64_t* a, int la, const uint64_t* b, int lb,
                                 const uint64_t* quo, int lq, const uint64_t* rem, int lr) {
    if (!(lq > 0 && lq <= la - lb + 1 && !is_zero4(quo + 4*(lq-1)))) fail();
    uint64_t q_b[(MAXW+1)*4];
    int q_b_len = (lb == 1) ? mul_short(quo, lq, b, q_b) : mul_long(quo, lq, b, lb, q_b);
    if (!(lr > 0)) fail();
    if (is_zero4(rem + 4*(lr-1))) {
        if (!(q_b_len == la && eq_words(a, q_b, la))) fail();
    } else {
        if (!(cmp_words(rem, lr, b, lb) < 0)) fail();   // rem < b
        uint64_t q_b_r[(MAXW+1)*4];
        int l = add_agtb(q_b, q_b_len, rem, lr, q_b_r);
        if (!(l == la && eq_words(a, q_b_r, la))) fail();
    }
}

// rem = a(la words) mod b(lb words). Returns rem length in words.
inline int rem_long(const uint64_t* a, int la, const uint64_t* b, int lb, uint64_t* rem) {
    int c = cmp_words(a, la, b, lb);
    if (c < 0) { for (int i = 0; i < la*4; ++i) rem[i] = a[i]; return la; }
    if (c == 0) { rem[0]=rem[1]=rem[2]=rem[3]=0; return 1; }
    uint64_t quo[MAXW*4]; uint64_t r[MAXW*4]; int lq_u64, lr_u64;
    fcall_bigint_div(a, la*4, b, lb*4, quo, &lq_u64, r, &lr_u64);
    int lq = lq_u64/4, lr = lr_u64/4;
    verify_division_long(a, la, b, lb, quo, lq, r, lr);
    for (int i = 0; i < lr*4; ++i) rem[i] = r[i];
    return lr;
}

// (a·b) mod m → out; returns out length in words. (a: la words, b: lb words)
inline int mul_and_reduce_long(const uint64_t* a, int la, const uint64_t* b, int lb,
                               const uint64_t* m, int lm, uint64_t* out) {
    uint64_t prod[2*MAXW*4];
    int pl = (lb == 1) ? mul_short(a, la, b, prod) : mul_long(a, la, b, lb, prod);
    return rem_long(prod, pl, m, lm, out);
}
// out = a(la words)². Squaring specialization: ~la·(la+1)/2 arith256 calls
// (diagonal a[i]² once + cross terms 2·a[i]·a[j] for i<j) versus mul_long's la²,
// trading the expensive arith256 for cheaper add256. Faithful to
// zisklib/lib/bigint/square_long.rs. Returns out length in words.
//
// Precondition: la ≥ 1, and for la>1 `a` has no leading zero word (a[la-1] != 0);
// callers pass trimmed lengths (rem_long/mul_and_reduce_long/square_long all
// return top-word-nonzero lengths). The diagonal pass writes every word
// out[0..2la-1] exactly once, so it fully initializes `out` (no separate zeroing).
// Since a² < B^(2la), the cross-term carry can never propagate past out[2la-1];
// `out` must hold ≥ 2la words.
inline int square_long(const uint64_t* a, int la, uint64_t* out) {
    uint64_t zero[4] = {0,0,0,0}, dh[4];
    // Diagonal terms a[i]·a[i] → out[2i]=dl, out[2i+1]=dh.
    for (int i = 0; i < la; ++i) {
        int k = 2*i;
        arith256(a + 4*i, a + 4*i, zero, out + 4*k, dh);
        cp4(out + 4*(k+1), dh);
    }
    // Cross terms 2·a[i]·a[j] (i<j), accumulated into out[i+j], out[i+j+1], out[i+j+2].
    for (int i = 0; i < la; ++i) {
        for (int j = i+1; j < la; ++j) {
            uint64_t l1[4], h1[4];
            arith256(a + 4*i, a + 4*j, zero, l1, h1);        // a[i]·a[j] = h1·B + l1
            // Double: 2·l1 = c0·B + low; 2·h1 + c0 = high·B + mid.
            uint64_t low_chunk[4], mid_chunk[4];
            uint64_t c0 = add256(l1, l1, 0, low_chunk);
            uint64_t high_chunk = add256(h1, h1, c0, mid_chunk);
            // Accumulate the low/mid/high chunks; write through t[] to avoid aliasing
            // an out[] slot as both an input and the output of add256.
            const int k = i + j;
            uint64_t t[4];
            uint64_t carry = add256(out + 4*k,     low_chunk, 0,     t); cp4(out + 4*k,     t);
            carry          = add256(out + 4*(k+1), mid_chunk, carry, t); cp4(out + 4*(k+1), t);
            uint64_t hi[4] = {high_chunk, 0, 0, 0};
            carry          = add256(out + 4*(k+2), hi,        carry, t); cp4(out + 4*(k+2), t);
            for (int idx = k+3; carry != 0; ++idx) {         // propagate final carry
                carry = add256(out + 4*idx, zero, carry, t); cp4(out + 4*idx, t);
            }
        }
    }
    return is_zero4(out + 4*(2*la - 1)) ? (2*la - 1) : (2*la);
}

// a² mod m → out; returns out length in words.
inline int square_and_reduce_long(const uint64_t* a, int la, const uint64_t* m, int lm, uint64_t* out) {
    uint64_t prod[2*MAXW*4];
    int pl;
    if (la == 1) { uint64_t o8[8]; pl = square_short(a, o8); for (int i=0;i<pl*4;++i) prod[i]=o8[i]; }
    else pl = square_long(a, la, prod);
    return rem_long(prod, pl, m, lm, out);
}

} // namespace zeg::bi

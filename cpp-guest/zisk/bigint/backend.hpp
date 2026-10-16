// backend.hpp — M1 of the MODEXP port: 256-bit primitives + fcall hints.
//
// Big integers are little-endian arrays of 64-bit limbs (groups of 4 = one
// "U256"). The inner 256-bit multiply-add is the ZisK arith256 precompile;
// division/exponent-bit decomposition come from fcall hints (verified by the
// higher layers). Dual backend selected by ZEG_ZISK (precompiles/fcalls vs
// portable software for host tests). Faithful to ziskos syscalls/arith256 +
// zisklib fcalls (bin_decomp id 16, bigint_div id 22).

#pragma once

#include <cstdint>
#include <cstring>

namespace zeg::bi {

// d(512) = a*b + c, all 256-bit (4 limbs); dl = low 4, dh = high 4.
// a,b,c point to [u64;4]; dl,dh to [u64;4].
#if defined(ZEG_ZISK)

inline void arith256(const uint64_t a[4], const uint64_t b[4], const uint64_t c[4],
                     uint64_t dl[4], uint64_t dh[4]) {
    struct { const uint64_t* a; const uint64_t* b; const uint64_t* c;
             uint64_t* dl; uint64_t* dh; } p{a, b, c, dl, dh};
    asm volatile("csrs 0x801, %0" : : "r"(&p) : "memory");
}
inline void arith256_mod(const uint64_t a[4], const uint64_t b[4], const uint64_t c[4],
                         const uint64_t m[4], uint64_t d[4]) {
    struct { const uint64_t* a; const uint64_t* b; const uint64_t* c;
             const uint64_t* module; uint64_t* d; } p{a, b, c, m, d};
    asm volatile("csrs 0x802, %0" : : "r"(&p) : "memory");
}

// 256-bit add: a + b + cin = cout|c (cout returned). CSR 0x811 (csrrs ret).
inline uint64_t add256(const uint64_t a[4], const uint64_t b[4], uint64_t cin, uint64_t c[4]) {
    struct { const uint64_t* a; const uint64_t* b; uint64_t cin; uint64_t* c; } p{a, b, cin, c};
    uint64_t cout;
    asm volatile("csrrs %0, 0x811, %1" : "=r"(cout) : "r"(&p) : "memory");
    return cout;
}

// fcall direct-value param push (bucket 1 → CSR 0x8F0) and result read.
inline void fc_param(uint64_t v) { asm volatile("csrs 0x8F0, %0" : : "r"(v) : "memory"); }
inline uint64_t fc_get() { uint64_t v; asm volatile("csrr %0, 0xFFE" : "=r"(v)); return v; }

// bin_decomp: bits of big int a[len_a] from MSB to LSB. Returns bit count;
// writes bits (each 0/1) into bits_out. (fcall id 16)
inline int fcall_bin_decomp(const uint64_t* a, int len_a, uint64_t* bits_out) {
    fc_param((uint64_t)len_a);
    for (int i = 0; i < len_a; ++i) fc_param(a[i]);
    asm volatile("csrwi 0x8C0, 16" : : : "memory");
    int n = (int)fc_get();
    for (int i = 0; i < n; ++i) bits_out[i] = fc_get();
    return n;
}
// bigint_div: a = b*quo + rem. Writes quo/rem, returns lengths via out-params. (id 22)
inline void fcall_bigint_div(const uint64_t* a, int len_a, const uint64_t* b, int len_b,
                             uint64_t* quo, int* len_quo, uint64_t* rem, int* len_rem) {
    fc_param((uint64_t)len_a);
    for (int i = 0; i < len_a; ++i) fc_param(a[i]);
    fc_param((uint64_t)len_b);
    for (int i = 0; i < len_b; ++i) fc_param(b[i]);
    asm volatile("csrwi 0x8C0, 22" : : : "memory");
    int lq = (int)fc_get(); for (int i = 0; i < lq; ++i) quo[i] = fc_get();
    int lr = (int)fc_get(); for (int i = 0; i < lr; ++i) rem[i] = fc_get();
    *len_quo = lq; *len_rem = lr;
}

#else  // ===================== portable software (host) =====================

inline void arith256(const uint64_t a[4], const uint64_t b[4], const uint64_t c[4],
                     uint64_t dl[4], uint64_t dh[4]) {
    uint64_t out[8] = {0};
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned __int128 t = (unsigned __int128)a[i]*b[j] + out[i+j] + carry;
            out[i+j] = (uint64_t)t; carry = (uint64_t)(t >> 64);
        }
        out[i+4] += carry;
    }
    unsigned __int128 carry = 0;            // + c (256-bit) into the low half
    for (int i = 0; i < 8; ++i) {
        uint64_t ci = (i < 4) ? c[i] : 0;
        unsigned __int128 s = (unsigned __int128)out[i] + ci + carry;
        out[i] = (uint64_t)s; carry = s >> 64;
    }
    for (int i = 0; i < 4; ++i) { dl[i] = out[i]; dh[i] = out[i+4]; }
}

namespace detail {
// out(4) = num(8) mod m(4), bit-by-bit.
inline void mod512(const uint64_t num[8], const uint64_t m[4], uint64_t out[4]) {
    uint64_t r[8] = {0};
    auto ge = [&](const uint64_t* rr) {
        for (int i = 7; i >= 4; --i) if (rr[i]) return true;
        for (int i = 3; i >= 0; --i) { if (rr[i] > m[i]) return true; if (rr[i] < m[i]) return false; }
        return true; };
    for (int i = 511; i >= 0; --i) {
        uint64_t carry = 0;
        for (int k = 0; k < 8; ++k) { uint64_t nx = r[k] >> 63; r[k] = (r[k] << 1) | carry; carry = nx; }
        r[0] |= (num[i >> 6] >> (i & 63)) & 1ULL;
        if (ge(r)) { unsigned __int128 br = 0;
            for (int k = 0; k < 8; ++k) { uint64_t mk = k < 4 ? m[k] : 0;
                unsigned __int128 t = (unsigned __int128)r[k] - mk - br; r[k] = (uint64_t)t; br = (t >> 64) & 1; } }
    }
    for (int i = 0; i < 4; ++i) out[i] = r[i];
}
}  // namespace detail

inline void arith256_mod(const uint64_t a[4], const uint64_t b[4], const uint64_t c[4],
                         const uint64_t m[4], uint64_t d[4]) {
    uint64_t dl[4], dh[4]; arith256(a, b, c, dl, dh);
    uint64_t num[8]; for (int i = 0; i < 4; ++i) { num[i] = dl[i]; num[i+4] = dh[i]; }
    detail::mod512(num, m, d);
}

// 256-bit add a+b+cin = cout|c (software).
inline uint64_t add256(const uint64_t a[4], const uint64_t b[4], uint64_t cin, uint64_t c[4]) {
    unsigned __int128 carry = cin;
    for (int i = 0; i < 4; ++i) { unsigned __int128 s = (unsigned __int128)a[i] + b[i] + carry;
        c[i] = (uint64_t)s; carry = s >> 64; }
    return (uint64_t)carry;
}

// bin_decomp (software): MSB→LSB bits of a[len_a], no leading zeros.
inline int fcall_bin_decomp(const uint64_t* a, int len_a, uint64_t* bits_out) {
    int top = -1;
    for (int i = len_a*64 - 1; i >= 0; --i) if ((a[i>>6] >> (i&63)) & 1ULL) { top = i; break; }
    if (top < 0) { return 0; }
    int n = 0;
    for (int i = top; i >= 0; --i) bits_out[n++] = (a[i>>6] >> (i&63)) & 1ULL;
    return n;
}
// bigint_div (software): a = b*quo + rem, bit-by-bit long division.
inline void fcall_bigint_div(const uint64_t* a, int len_a, const uint64_t* b, int len_b,
                             uint64_t* quo, int* len_quo, uint64_t* rem, int* len_rem) {
    // r accumulates the remainder (up to len_b+1 limbs); q the quotient (len_a limbs).
    const int RW = len_b + 1, QW = len_a;
    uint64_t r[64] = {0}; uint64_t q[64] = {0};   // 64 limbs = 4096 bits, ample for EIP-7823
    auto ge_b = [&]() {                            // r >= b ?
        for (int i = RW-1; i >= len_b; --i) if (r[i]) return true;
        for (int i = len_b-1; i >= 0; --i) { if (r[i] > b[i]) return true; if (r[i] < b[i]) return false; }
        return true; };
    for (int i = len_a*64 - 1; i >= 0; --i) {
        uint64_t carry = 0;                        // r <<= 1
        for (int k = 0; k < RW; ++k) { uint64_t nx = r[k] >> 63; r[k] = (r[k] << 1) | carry; carry = nx; }
        r[0] |= (a[i>>6] >> (i&63)) & 1ULL;
        if (ge_b()) {
            unsigned __int128 br = 0;               // r -= b
            for (int k = 0; k < RW; ++k) { uint64_t bk = k < len_b ? b[k] : 0;
                unsigned __int128 t = (unsigned __int128)r[k] - bk - br; r[k] = (uint64_t)t; br = (t >> 64) & 1; }
            q[i>>6] |= 1ULL << (i&63);              // set quotient bit
        }
    }
    // Match the emulator's bigint_div: quo/rem lengths rounded up to a multiple
    // of 4 limbs (one U256 word), zero-padded; minimum 4.
    int lq = QW; while (lq > 1 && q[lq-1] == 0) --lq; lq = ((lq + 3) / 4) * 4;
    int lr = len_b; while (lr > 1 && r[lr-1] == 0) --lr; lr = ((lr + 3) / 4) * 4;
    for (int i = 0; i < lq; ++i) quo[i] = q[i];   // q is zero-initialised beyond
    for (int i = 0; i < lr; ++i) rem[i] = r[i];   // r is zero-initialised beyond
    *len_quo = lq; *len_rem = lr;
}

#endif  // backend

// ---- 256-bit word helpers (operate on one 4-limb word) --------------------
// Backend-agnostic (used by bignum.hpp and the EVM div/mod opcodes); live here,
// next to arith256, so callers need only backend.hpp.
inline bool is_zero4(const uint64_t* x) { return !x[0] && !x[1] && !x[2] && !x[3]; }
inline bool is_one4 (const uint64_t* x) { return x[0]==1 && !x[1] && !x[2] && !x[3]; }
inline bool eq4(const uint64_t* a, const uint64_t* b) { return a[0]==b[0]&&a[1]==b[1]&&a[2]==b[2]&&a[3]==b[3]; }
inline bool lt4(const uint64_t* a, const uint64_t* b) {
    for (int i = 3; i >= 0; --i) if (a[i] != b[i]) return a[i] < b[i];
    return false;
}
inline void cp4(uint64_t* d, const uint64_t* s) { d[0]=s[0]; d[1]=s[1]; d[2]=s[2]; d[3]=s[3]; }
inline void fail() { for (;;) {} }  // unreachable: a hint/invariant was violated

// ---- verified 256-bit division (q = a/b, r = a%b; caller guarantees b != 0) -
// The quotient/remainder come from the free `bigint_div` fcall — unconstrained
// prover advice. One arith256 (q*b + r) plus three 256-bit compares make the
// result sound: a == q*b + r with no overflow (q*b+r fits 256 bits since
// q <= a < 2^256 and r < b) and r < b. ~1 arith256 (1440) vs software long
// division (~10^4 cost). Used by the EVM DIV/MOD/SDIV/SMOD opcodes in both
// backends. On the host (software backend.hpp) the same check runs and stays an
// honest reference.
inline void udivmod4(const uint64_t a[4], const uint64_t b[4],
                     uint64_t q[4], uint64_t r[4]) {
    uint64_t qq[8] = {0}, rr[8] = {0};
    int lq = 0, lr = 0;
    fcall_bigint_div(a, 4, b, 4, qq, &lq, rr, &lr);  // hint: a = b*q + r
    cp4(q, qq);
    cp4(r, rr);
    uint64_t dl[4], dh[4];
    arith256(q, b, r, dl, dh);  // q*b + r  (r folded in as the c operand)
    if (!eq4(dl, a) || !is_zero4(dh) || !lt4(r, b)) fail();
}

} // namespace zeg::bi

// fp.hpp — BLS12-381 base field Fp (384-bit) for the KZG point-eval port.
//
// Layer 1 of the self-contained C++ port of ziskos's zisklib BLS12-381 (see the
// KZG plan). Dual backend, selected by ZEG_ZISK (mirrors secp256k1.cpp):
//   ZEG_ZISK : field mul/add via the ZisK arith384_mod precompile (CSR 0x80B);
//              inverse/sqrt via fcall hints (ids 10/11), verified in-circuit.
//   else     : portable software (768-bit mul + reduce, Fermat inverse, p≡3 mod4
//              sqrt) — used for host unit tests against known-answer vectors.
//
// Faithful to ziskos/.../zisklib/lib/bls12_381/fp.rs and fcalls_impl. Limbs are
// little-endian uint64_t[6]; Fp is the (a*b+c) mod p machine of arith384_mod.

#pragma once

#include <cstdint>
#include <cstring>

namespace zeg::bls {

struct Fp { uint64_t c[6]; };

// ---- constants (little-endian limbs), from zisklib constants.rs ------------
inline constexpr Fp FP_P = {{0xB9FEFFFFFFFFAAABULL, 0x1EABFFFEB153FFFFULL,
                             0x6730D2A0F6B0F624ULL, 0x64774B84F38512BFULL,
                             0x4B1BA7B6434BACD7ULL, 0x1A0111EA397FE69AULL}};
inline constexpr Fp FP_P_MINUS_ONE = {{0xB9FEFFFFFFFFAAAAULL, 0x1EABFFFEB153FFFFULL,
                                       0x6730D2A0F6B0F624ULL, 0x64774B84F38512BFULL,
                                       0x4B1BA7B6434BACD7ULL, 0x1A0111EA397FE69AULL}};
inline constexpr Fp FP_NQR = {{2, 0, 0, 0, 0, 0}};  // a non-quadratic residue
inline constexpr Fp FP_ZERO = {{0, 0, 0, 0, 0, 0}};
inline constexpr Fp FP_ONE = {{1, 0, 0, 0, 0, 0}};

inline bool fp_eq(const Fp& a, const Fp& b) {
    return std::memcmp(a.c, b.c, sizeof(a.c)) == 0;
}
inline bool fp_is_zero(const Fp& a) { return fp_eq(a, FP_ZERO); }
inline uint64_t fp_sgn0(const Fp& a) { return a.c[0] & 1; }  // sign function
inline bool fp_lt(const Fp& a, const Fp& b) {  // a < b as 384-bit integers
    for (int i = 5; i >= 0; --i) { if (a.c[i] < b.c[i]) return true; if (a.c[i] > b.c[i]) return false; }
    return false;
}

// ===========================================================================
// Backend: arith384_mod (d = a*b + c mod p) and the inverse/sqrt fcall hints.
// ===========================================================================
#if defined(ZEG_ZISK)

// ZisK arith384_mod precompile (CSR 0x80B). Params layout = SyscallArith384ModParams.
inline void fp_muladd_mod(const Fp& a, const Fp& b, const Fp& c, const Fp& m, Fp& d) {
    struct { const uint64_t* a; const uint64_t* b; const uint64_t* c;
             const uint64_t* module; uint64_t* d; } p{a.c, b.c, c.c, m.c, d.c};
    asm volatile("csrs 0x80B, %0" : : "r"(&p) : "memory");
}

inline uint64_t fcall_get() {
    uint64_t v; asm volatile("csrr %0, 0xFFE" : "=r"(v)); return v;
}
// fcall param push: bucket 8 (6-word Fp rounds up to 8) → CSR 0x8F0+3 = 0x8F3.
inline void fcall_param_fp(const Fp& x) {
    uint64_t buf[8] = {x.c[0], x.c[1], x.c[2], x.c[3], x.c[4], x.c[5], 0, 0};
    const uint64_t* p = buf;
    asm volatile("csrs 0x8F3, %0" : : "r"(p) : "memory");
}
// 1/x mod p (hint only; verified by the caller).
inline Fp fcall_fp_inv(const Fp& x) {
    fcall_param_fp(x);
    asm volatile("csrwi 0x8C0, 10" : : : "memory");  // FCALL_BLS12_381_FP_INV_ID
    Fp r; for (int i = 0; i < 6; ++i) r.c[i] = fcall_get();
    return r;
}
// sqrt hint: returns is_qr in *is_qr and the candidate root (sqrt^2 == x or x*NQR).
inline Fp fcall_fp_sqrt(const Fp& x, bool* is_qr) {
    fcall_param_fp(x);
    asm volatile("csrwi 0x8C0, 11" : : : "memory");  // FCALL_BLS12_381_FP_SQRT_ID
    *is_qr = (fcall_get() == 1);
    Fp r; for (int i = 0; i < 6; ++i) r.c[i] = fcall_get();
    return r;
}

#else  // ===================== portable software (host) =====================

namespace detail {
// 6-limb compare a<b.
inline bool lt6(const uint64_t a[6], const uint64_t b[6]) {
    for (int i = 5; i >= 0; --i) { if (a[i] < b[i]) return true; if (a[i] > b[i]) return false; }
    return false;
}
// 768-bit >= (m zero-extended to 12 limbs).
inline bool ge_768_384(const uint64_t r[12], const uint64_t m[6]) {
    for (int i = 11; i >= 6; --i) if (r[i]) return true;
    for (int i = 5; i >= 0; --i) { if (r[i] > m[i]) return true; if (r[i] < m[i]) return false; }
    return true;
}
inline void sub_m_768(uint64_t r[12], const uint64_t m[6]) {
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 12; ++i) {
        uint64_t mi = (i < 6) ? m[i] : 0;
        unsigned __int128 t = (unsigned __int128)r[i] - mi - borrow;
        r[i] = (uint64_t)t; borrow = (t >> 64) & 1;
    }
}
inline void mul6(const uint64_t a[6], const uint64_t b[6], uint64_t out[12]) {
    for (int i = 0; i < 12; ++i) out[i] = 0;
    for (int i = 0; i < 6; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 6; ++j) {
            unsigned __int128 t = (unsigned __int128)a[i] * b[j] + out[i + j] + carry;
            out[i + j] = (uint64_t)t; carry = (uint64_t)(t >> 64);
        }
        out[i + 6] += carry;
    }
}
// out = num (768) mod m (384), bit-by-bit.
inline void mod768(const uint64_t num[12], const uint64_t m[6], uint64_t out[6]) {
    uint64_t r[12] = {0};
    for (int i = 767; i >= 0; --i) {
        uint64_t carry = 0;
        for (int k = 0; k < 12; ++k) { uint64_t nx = (r[k] >> 63) & 1; r[k] = (r[k] << 1) | carry; carry = nx; }
        r[0] |= (num[i >> 6] >> (i & 63)) & 1ULL;
        if (ge_768_384(r, m)) sub_m_768(r, m);
    }
    for (int i = 0; i < 6; ++i) out[i] = r[i];
}
}  // namespace detail

// d = (a*b + c) mod m, software.
inline void fp_muladd_mod(const Fp& a, const Fp& b, const Fp& c, const Fp& m, Fp& d) {
    uint64_t t[12]; detail::mul6(a.c, b.c, t);
    unsigned __int128 carry = 0;  // t += c
    for (int i = 0; i < 12; ++i) {
        uint64_t ci = (i < 6) ? c.c[i] : 0;
        unsigned __int128 s = (unsigned __int128)t[i] + ci + carry;
        t[i] = (uint64_t)s; carry = s >> 64;
    }
    detail::mod768(t, m.c, d.c);
}

namespace detail {
// modular exponentiation base^e mod p (e little-endian 6 limbs), software.
inline Fp modpow(const Fp& base, const uint64_t e[6]) {
    Fp res = FP_ONE;
    for (int i = 383; i >= 0; --i) {
        Fp t; fp_muladd_mod(res, res, FP_ZERO, FP_P, t); res = t;            // square
        if ((e[i >> 6] >> (i & 63)) & 1ULL) { fp_muladd_mod(res, base, FP_ZERO, FP_P, t); res = t; }  // mul
    }
    return res;
}
}  // namespace detail

// 1/x mod p via Fermat (x^(p-2)); software stand-in for the fcall hint.
inline Fp fcall_fp_inv(const Fp& x) {
    uint64_t e[6]; std::memcpy(e, FP_P.c, sizeof(e)); e[0] -= 2;  // p-2 (p[0] odd)
    return detail::modpow(x, e);
}
// sqrt hint: candidate = x^((p+1)/4) (p ≡ 3 mod 4); is_qr iff candidate^2 == x,
// else returns sqrt(x*NQR) — mirrors fcalls_impl/bls12_381/fp_sqrt.rs.
inline Fp fcall_fp_sqrt(const Fp& x, bool* is_qr) {
    uint64_t e[6]; std::memcpy(e, FP_P.c, sizeof(e));  // (p+1)/4
    unsigned __int128 carry = 1;                       // p+1
    for (int i = 0; i < 6; ++i) { unsigned __int128 s = (unsigned __int128)e[i] + carry; e[i] = (uint64_t)s; carry = s >> 64; }
    uint64_t rem = 0;                                  // >>2
    for (int i = 5; i >= 0; --i) { uint64_t nrem = e[i] & 3; e[i] = (e[i] >> 2) | (rem << 62); rem = nrem; }
    Fp cand = detail::modpow(x, e);
    Fp sq; fp_muladd_mod(cand, cand, FP_ZERO, FP_P, sq);
    if (fp_eq(sq, x)) { *is_qr = true; return cand; }
    Fp xnqr; fp_muladd_mod(x, FP_NQR, FP_ZERO, FP_P, xnqr);
    *is_qr = false;
    return detail::modpow(xnqr, e);
}

#endif  // backend

// ===========================================================================
// Fp ops (shared) — all expressed through fp_muladd_mod, like zisklib fp.rs.
// ===========================================================================
inline Fp fp_add(const Fp& x, const Fp& y) { Fp d; fp_muladd_mod(x, FP_ONE, y, FP_P, d); return d; }          // x*1 + y
inline Fp fp_dbl(const Fp& x) { Fp d; const Fp two{{2,0,0,0,0,0}}; fp_muladd_mod(x, two, FP_ZERO, FP_P, d); return d; }
inline Fp fp_sub(const Fp& x, const Fp& y) { Fp d; fp_muladd_mod(y, FP_P_MINUS_ONE, x, FP_P, d); return d; }   // y*(-1) + x
inline Fp fp_neg(const Fp& x) { Fp d; fp_muladd_mod(x, FP_P_MINUS_ONE, FP_ZERO, FP_P, d); return d; }
inline Fp fp_mul(const Fp& x, const Fp& y) { Fp d; fp_muladd_mod(x, y, FP_ZERO, FP_P, d); return d; }
inline Fp fp_sqr(const Fp& x) { Fp d; fp_muladd_mod(x, x, FP_ZERO, FP_P, d); return d; }

// 1/x mod p (0 ↦ 0). Hint then verify x·inv == 1.
inline Fp fp_inv(const Fp& x) {
    if (fp_is_zero(x)) return x;
    Fp inv = fcall_fp_inv(x);
    Fp chk; fp_muladd_mod(x, inv, FP_ZERO, FP_P, chk);
    if (!fp_eq(chk, FP_ONE)) { for (;;) {} }  // bad hint: must never happen
    return inv;
}
// sqrt: returns (root, is_qr). When is_qr, root²==x; else root²==x·NQR. Verified.
inline Fp fp_sqrt(const Fp& x, bool* is_qr) {
    bool qr; Fp root = fcall_fp_sqrt(x, &qr);
    Fp sq; fp_muladd_mod(root, root, FP_ZERO, FP_P, sq);
    if (qr) { if (!fp_eq(sq, x)) { for (;;) {} } }
    else    { Fp xn; fp_muladd_mod(x, FP_NQR, FP_ZERO, FP_P, xn); if (!fp_eq(sq, xn)) { for (;;) {} } }
    *is_qr = qr;
    return root;
}

// 48-byte big-endian → Fp (little-endian limbs). From zisklib fp.rs.
inline Fp fp_from_bytes_be(const uint8_t b[48]) {
    Fp r = FP_ZERO;
    for (int i = 0; i < 6; ++i)
        for (int j = 0; j < 8; ++j)
            r.c[5 - i] |= (uint64_t)b[i * 8 + j] << (8 * (7 - j));
    return r;
}
inline void fp_to_bytes_be(const Fp& x, uint8_t b[48]) {
    for (int i = 0; i < 6; ++i)
        for (int j = 0; j < 8; ++j)
            b[i * 8 + j] = (uint8_t)(x.c[5 - i] >> (8 * (7 - j)));
}

} // namespace zeg::bls

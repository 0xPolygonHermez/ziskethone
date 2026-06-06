// fp2.hpp — BLS12-381 quadratic extension Fp2 = Fp[u]/(u²+1).
//
// Layer 2 of the KZG BLS12-381 port. Fp2 = c0 + c1·u (re, im), stored as two
// contiguous Fp so the 12-u64 block matches ziskos's SyscallComplex384.
// Dual backend (ZEG_ZISK): add/sub/mul via the complex precompiles
// (CSR 0x80E/0x80F/0x810); inv/sqrt via fcall hints (ids 12/13), verified.
// Software path mirrors zisklib fcalls_impl (Algorithm 9 sqrt) for host tests.
// Faithful to zisklib/lib/bls12_381/fp2.rs.

#pragma once

#include <cstdint>
#include "fp.hpp"

namespace zeg::bls {

struct Fp2 { Fp c0; Fp c1; };  // c0 + c1·u ; 12 contiguous u64

inline constexpr Fp2 FP2_ZERO = {FP_ZERO, FP_ZERO};
inline constexpr Fp2 FP2_ONE  = {FP_ONE,  FP_ZERO};
inline constexpr Fp2 FP2_U    = {FP_ZERO, FP_ONE};   // i = u
inline constexpr Fp2 FP2_NQR  = {FP_ONE,  FP_ONE};   // 1 + u (non-residue)

inline bool fp2_eq(const Fp2& a, const Fp2& b) { return fp_eq(a.c0, b.c0) && fp_eq(a.c1, b.c1); }
inline bool fp2_is_zero(const Fp2& a) { return fp_is_zero(a.c0) && fp_is_zero(a.c1); }
inline uint64_t fp2_sgn0(const Fp2& a) {
    uint64_t s0 = a.c0.c[0] & 1, z0 = fp_is_zero(a.c0) ? 1 : 0, s1 = a.c1.c[0] & 1;
    return s0 | (z0 & s1);
}

// ===========================================================================
// Backend: add/sub/mul + the inv/sqrt fcall hints.
// ===========================================================================
#if defined(ZEG_ZISK)

namespace detail {
struct CplxParams { uint64_t* f1; const uint64_t* f2; };
inline Fp2 cplx_op(unsigned csr, const Fp2& a, const Fp2& b) {
    Fp2 f1 = a, f2 = b;
    CplxParams p{ reinterpret_cast<uint64_t*>(&f1), reinterpret_cast<const uint64_t*>(&f2) };
    switch (csr) {
        case 0x80E: asm volatile("csrs 0x80E, %0" : : "r"(&p) : "memory"); break;
        case 0x80F: asm volatile("csrs 0x80F, %0" : : "r"(&p) : "memory"); break;
        default:    asm volatile("csrs 0x810, %0" : : "r"(&p) : "memory"); break;
    }
    return f1;
}
}  // namespace detail
inline Fp2 fp2_add(const Fp2& a, const Fp2& b) { return detail::cplx_op(0x80E, a, b); }
inline Fp2 fp2_sub(const Fp2& a, const Fp2& b) { return detail::cplx_op(0x80F, a, b); }
inline Fp2 fp2_mul(const Fp2& a, const Fp2& b) { return detail::cplx_op(0x810, a, b); }

// fcall param push for a 12-word Fp2: bucket 12 → CSR 0x8F0+4 = 0x8F4.
inline void fcall_param_fp2(const Fp2& x) {
    const uint64_t* p = reinterpret_cast<const uint64_t*>(&x);
    asm volatile("csrs 0x8F4, %0" : : "r"(p) : "memory");
}
inline Fp2 fcall_fp2_inv(const Fp2& x) {
    fcall_param_fp2(x);
    asm volatile("csrwi 0x8C0, 12" : : : "memory");  // FCALL_BLS12_381_FP2_INV_ID
    Fp2 r; uint64_t* o = reinterpret_cast<uint64_t*>(&r);
    for (int i = 0; i < 12; ++i) o[i] = fcall_get();
    return r;
}
inline Fp2 fcall_fp2_sqrt(const Fp2& x, bool* is_qr) {
    // zisklib pushes the fp2_sqrt input via bucket 16 (CSR 0x8F5), not 12.
    uint64_t buf[16] = {x.c0.c[0],x.c0.c[1],x.c0.c[2],x.c0.c[3],x.c0.c[4],x.c0.c[5],
                        x.c1.c[0],x.c1.c[1],x.c1.c[2],x.c1.c[3],x.c1.c[4],x.c1.c[5],0,0,0,0};
    const uint64_t* p = buf;
    asm volatile("csrs 0x8F5, %0" : : "r"(p) : "memory");
    asm volatile("csrwi 0x8C0, 13" : : : "memory");  // FCALL_BLS12_381_FP2_SQRT_ID
    *is_qr = (fcall_get() == 1);
    Fp2 r; uint64_t* o = reinterpret_cast<uint64_t*>(&r);
    for (int i = 0; i < 12; ++i) o[i] = fcall_get();
    return r;
}

#else  // ===================== portable software (host) =====================

inline Fp2 fp2_add(const Fp2& a, const Fp2& b) { return { fp_add(a.c0, b.c0), fp_add(a.c1, b.c1) }; }
inline Fp2 fp2_sub(const Fp2& a, const Fp2& b) { return { fp_sub(a.c0, b.c0), fp_sub(a.c1, b.c1) }; }
// (a0+a1 u)(b0+b1 u) = (a0 b0 - a1 b1) + (a0 b1 + a1 b0) u   (u² = -1)
inline Fp2 fp2_mul(const Fp2& a, const Fp2& b) {
    Fp2 r;
    r.c0 = fp_sub(fp_mul(a.c0, b.c0), fp_mul(a.c1, b.c1));
    r.c1 = fp_add(fp_mul(a.c0, b.c1), fp_mul(a.c1, b.c0));
    return r;
}

namespace detail {
inline Fp2 fp2_exp(const Fp2& a, const uint64_t e[6]) {  // a^e, e little-endian 6 limbs
    Fp2 res = FP2_ONE, base = a;
    for (int i = 0; i < 384; ++i) {
        if ((e[i >> 6] >> (i & 63)) & 1ULL) res = fp2_mul(res, base);
        base = fp2_mul(base, base);
    }
    return res;
}
inline void p_minus_3_div_4(uint64_t e[6]) {            // (p-3)/4
    for (int i = 0; i < 6; ++i) e[i] = FP_P.c[i];
    e[0] -= 3;
    uint64_t rem = 0;
    for (int i = 5; i >= 0; --i) { uint64_t nr = e[i] & 3; e[i] = (e[i] >> 2) | (rem << 62); rem = nr; }
}
inline void p_minus_1_div_2(uint64_t e[6]) {            // (p-1)/2
    for (int i = 0; i < 6; ++i) e[i] = FP_P.c[i];
    e[0] -= 1;
    uint64_t rem = 0;
    for (int i = 5; i >= 0; --i) { uint64_t nr = e[i] & 1; e[i] = (e[i] >> 1) | (rem << 63); rem = nr; }
}
inline Fp2 fp2_conj(const Fp2& a) { return { a.c0, fp_neg(a.c1) }; }
inline constexpr Fp2 FP2_P_MINUS_ONE = {FP_P_MINUS_ONE, FP_ZERO};

// Algorithm 9 (eprint 2012/685): sqrt over Fp2, p ≡ 3 (mod 4).
inline bool fp2_sqrt_core(const Fp2& a, Fp2& out) {
    uint64_t e34[6]; p_minus_3_div_4(e34);
    Fp2 a1 = fp2_exp(a, e34);
    Fp2 a1_a = fp2_mul(a1, a);
    Fp2 alpha = fp2_mul(a1, a1_a);
    Fp2 a0 = fp2_mul(fp2_conj(alpha), alpha);
    if (fp2_eq(a0, FP2_P_MINUS_ONE)) { out = FP2_ZERO; return false; }
    Fp2 x0 = a1_a;
    if (fp2_eq(alpha, FP2_P_MINUS_ONE)) {
        out = fp2_mul(FP2_U, x0);
    } else {
        uint64_t e12[6]; p_minus_1_div_2(e12);
        Fp2 b = fp2_exp(fp2_add(FP2_ONE, alpha), e12);
        out = fp2_mul(b, x0);
    }
    return true;
}
}  // namespace detail

// 1/a software (fcall stand-in): inv = conj(a)/(a0²+a1²).
inline Fp2 fcall_fp2_inv(const Fp2& a) {
    Fp denom = fp_add(fp_mul(a.c0, a.c0), fp_mul(a.c1, a.c1));
    Fp dinv = fcall_fp_inv(denom);  // host fp inverse
    return { fp_mul(a.c0, dinv), fp_mul(fp_neg(a.c1), dinv) };
}
inline Fp2 fcall_fp2_sqrt(const Fp2& a, bool* is_qr) {
    Fp2 root;
    bool qr = detail::fp2_sqrt_core(a, root);
    *is_qr = qr;
    if (qr) return root;
    Fp2 anqr = fp2_mul(a, FP2_NQR);
    detail::fp2_sqrt_core(anqr, root);  // root of a·NQR
    return root;
}

#endif  // backend

// ===========================================================================
// Shared Fp2 ops.
// ===========================================================================
inline Fp2 fp2_dbl(const Fp2& a) { return fp2_add(a, a); }
inline Fp2 fp2_neg(const Fp2& a) { return { fp_neg(a.c0), fp_neg(a.c1) }; }
inline Fp2 fp2_sqr(const Fp2& a) { return fp2_mul(a, a); }
inline Fp2 fp2_conjugate(const Fp2& a) { return { a.c0, fp_neg(a.c1) }; }
inline Fp2 fp2_frobenius(const Fp2& a) { return fp2_conjugate(a); }  // x^p in Fp2
inline Fp2 fp2_scalar_mul(const Fp2& a, const Fp& s) { return { fp_mul(a.c0, s), fp_mul(a.c1, s) }; }
// multiply by the Fp6 non-residue (1+u): (c0-c1) + (c0+c1)u
inline Fp2 fp2_mul_by_nonresidue(const Fp2& a) { return { fp_sub(a.c0, a.c1), fp_add(a.c0, a.c1) }; }

// 1/a (0↦0). Hint then verify a·inv == 1.
inline Fp2 fp2_inv(const Fp2& a) {
    if (fp2_is_zero(a)) return a;
    Fp2 inv = fcall_fp2_inv(a);
    if (!fp2_eq(fp2_mul(a, inv), FP2_ONE)) { for (;;) {} }
    return inv;
}
// sqrt: (root, is_qr). is_qr ⇒ root²==a, else root²==a·NQR. Verified.
inline Fp2 fp2_sqrt(const Fp2& a, bool* is_qr) {
    bool qr; Fp2 root = fcall_fp2_sqrt(a, &qr);
    Fp2 sq = fp2_mul(root, root);
    if (qr) { if (!fp2_eq(sq, a)) { for (;;) {} } }
    else    { if (!fp2_eq(sq, fp2_mul(a, FP2_NQR))) { for (;;) {} } }
    *is_qr = qr;
    return root;
}

// 96-byte BE (c0||c1) → Fp2.
inline Fp2 fp2_from_bytes_be(const uint8_t b[96]) {
    return { fp_from_bytes_be(b), fp_from_bytes_be(b + 48) };
}

} // namespace zeg::bls

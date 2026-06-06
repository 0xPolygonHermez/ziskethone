// fp2.hpp — BN254 quadratic extension Fp2 = Fp[u]/(u²+1).
//
// Layer 2 of the BN254 port. Fp2 = c0 + c1·u (re, im), two contiguous Fp so the
// 8-u64 block matches ziskos's SyscallComplex256. Dual backend (ZEG_ZISK):
// add/sub/mul via the complex precompiles (CSR 0x808/0x809/0x80A); inv via the
// fp2_inv fcall hint (id 7), verified. Faithful to zisklib/lib/bn254/fp2.rs.
// The Fp6 non-residue is ξ = 9 + u (BN254), unlike BLS's 1 + u.

#pragma once

#include <cstdint>
#include "fp.hpp"

namespace zeg::bn {

struct Fp2 { Fp c0; Fp c1; };  // c0 + c1·u ; 8 contiguous u64

inline constexpr Fp2 FP2_ZERO = {FP_ZERO, FP_ZERO};
inline constexpr Fp2 FP2_ONE  = {FP_ONE,  FP_ZERO};
inline constexpr Fp2 FP2_U    = {FP_ZERO, FP_ONE};   // i = u

inline bool fp2_eq(const Fp2& a, const Fp2& b) { return fp_eq(a.c0, b.c0) && fp_eq(a.c1, b.c1); }
inline bool fp2_is_zero(const Fp2& a) { return fp_is_zero(a.c0) && fp_is_zero(a.c1); }

// ===========================================================================
// Backend: add/sub/mul + the fp2_inv fcall hint.
// ===========================================================================
#if defined(ZEG_ZISK)

namespace detail {
struct CplxParams { uint64_t* f1; const uint64_t* f2; };
inline Fp2 cplx_op(unsigned csr, const Fp2& a, const Fp2& b) {
    Fp2 f1 = a, f2 = b;
    CplxParams p{ reinterpret_cast<uint64_t*>(&f1), reinterpret_cast<const uint64_t*>(&f2) };
    switch (csr) {
        case 0x808: asm volatile("csrs 0x808, %0" : : "r"(&p) : "memory"); break;
        case 0x809: asm volatile("csrs 0x809, %0" : : "r"(&p) : "memory"); break;
        default:    asm volatile("csrs 0x80A, %0" : : "r"(&p) : "memory"); break;
    }
    return f1;
}
}  // namespace detail
inline Fp2 fp2_add(const Fp2& a, const Fp2& b) { return detail::cplx_op(0x808, a, b); }
inline Fp2 fp2_sub(const Fp2& a, const Fp2& b) { return detail::cplx_op(0x809, a, b); }
inline Fp2 fp2_mul(const Fp2& a, const Fp2& b) { return detail::cplx_op(0x80A, a, b); }

// fcall param push for an 8-word Fp2: bucket 8 → CSR 0x8F0+3 = 0x8F3.
inline Fp2 fcall_fp2_inv(const Fp2& x) {
    const uint64_t* p = reinterpret_cast<const uint64_t*>(&x);
    asm volatile("csrs 0x8F3, %0" : : "r"(p) : "memory");
    asm volatile("csrwi 0x8C0, 7" : : : "memory");  // FCALL_BN254_FP2_INV_ID
    Fp2 r; uint64_t* o = reinterpret_cast<uint64_t*>(&r);
    for (int i = 0; i < 8; ++i) o[i] = fcall_get();
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
// 1/a software (fcall stand-in): inv = conj(a)/(a0²+a1²).
inline Fp2 fcall_fp2_inv(const Fp2& a) {
    Fp denom = fp_add(fp_mul(a.c0, a.c0), fp_mul(a.c1, a.c1));
    Fp dinv = fcall_fp_inv(denom);
    return { fp_mul(a.c0, dinv), fp_mul(fp_neg(a.c1), dinv) };
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
// multiply by the Fp6 non-residue ξ = 9 + u: (9 a0 - a1) + (a0 + 9 a1) u
inline Fp2 fp2_mul_by_nonresidue(const Fp2& a) {
    Fp a0_9 = fp_add(fp_add(fp_add(a.c0, a.c0), fp_add(a.c0, a.c0)), fp_add(fp_add(a.c0, a.c0), fp_add(a.c0, a.c0)));  // 8·a0
    a0_9 = fp_add(a0_9, a.c0);  // 9·a0
    Fp a1_9 = fp_add(fp_add(fp_add(a.c1, a.c1), fp_add(a.c1, a.c1)), fp_add(fp_add(a.c1, a.c1), fp_add(a.c1, a.c1)));  // 8·a1
    a1_9 = fp_add(a1_9, a.c1);  // 9·a1
    return { fp_sub(a0_9, a.c1), fp_add(a.c0, a1_9) };
}

// 1/a (0↦0). Hint then verify a·inv == 1.
inline Fp2 fp2_inv(const Fp2& a) {
    if (fp2_is_zero(a)) return a;
    Fp2 inv = fcall_fp2_inv(a);
    if (!fp2_eq(fp2_mul(a, inv), FP2_ONE)) { for (;;) {} }
    return inv;
}

// 64-byte BE (c0||c1) → Fp2.
inline Fp2 fp2_from_bytes_be(const uint8_t b[64]) {
    return { fp_from_bytes_be(b), fp_from_bytes_be(b + 32) };
}

} // namespace zeg::bn

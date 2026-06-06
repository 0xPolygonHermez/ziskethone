// fp12.hpp — BLS12-381 dodecic extension Fp12 = Fp6[w]/(w² - v).
//
// Layer 3b of the KZG port. Fp12 = c0 + c1·w (two Fp6, 72 u64). Built on Fp6/
// Fp2, backend-agnostic. Includes mul/sqr/inv/conjugate, the sparse mul used by
// the Miller loop, and the two Frobenius endomorphisms (x^p, x^{p²}).
// Faithful to zisklib/lib/bls12_381/fp12.rs + the FROBENIUS_GAMMA* constants.

#pragma once

#include "fp6.hpp"

namespace zeg::bls {

struct Fp12 { Fp6 c0, c1; };  // c0 + c1·w

inline constexpr Fp12 FP12_ZERO = {FP6_ZERO, FP6_ZERO};
inline constexpr Fp12 FP12_ONE  = {FP6_ONE,  FP6_ZERO};

inline bool fp12_eq(const Fp12& a, const Fp12& b) { return fp6_eq(a.c0,b.c0) && fp6_eq(a.c1,b.c1); }
inline bool fp12_is_zero(const Fp12& a) { return fp6_is_zero(a.c0) && fp6_is_zero(a.c1); }

// ---- Frobenius coefficients (from zisklib constants.rs) --------------------
// γ11,γ12,γ13,γ15 ∈ Fp2 ; γ14, γ21..γ25 ∈ Fp.
inline constexpr Fp2 GAMMA11 = {{{0x8D0775ED92235FB8ULL,0xF67EA53D63E7813DULL,0x7B2443D784BAB9C4ULL,0x0FD603FD3CBD5F4FULL,0xC231BEB4202C0D1FULL,0x1904D3BF02BB0667ULL}},
                                {{0x2CF78A126DDC4AF3ULL,0x282D5AC14D6C7EC2ULL,0xEC0C8EC971F63C5FULL,0x54A14787B6C7B36FULL,0x88E9E902231F9FB8ULL,0x00FC3E2B36C4E032ULL}}};
inline constexpr Fp2 GAMMA12 = {{{0,0,0,0,0,0}},
                                {{0x8BFD00000000AAACULL,0x409427EB4F49FFFDULL,0x897D29650FB85F9BULL,0xAA0D857D89759AD4ULL,0xEC02408663D4DE85ULL,0x1A0111EA397FE699ULL}}};
inline constexpr Fp2 GAMMA13 = {{{0xC81084FBEDE3CC09ULL,0xEE67992F72EC05F4ULL,0x77F76E17009241C5ULL,0x48395DABC2D3435EULL,0x6831E36D6BD17FFEULL,0x06AF0E0437FF400BULL}},
                                {{0xC81084FBEDE3CC09ULL,0xEE67992F72EC05F4ULL,0x77F76E17009241C5ULL,0x48395DABC2D3435EULL,0x6831E36D6BD17FFEULL,0x06AF0E0437FF400BULL}}};
inline constexpr Fp  GAMMA14 = {{0x8BFD00000000AAADULL,0x409427EB4F49FFFDULL,0x897D29650FB85F9BULL,0xAA0D857D89759AD4ULL,0xEC02408663D4DE85ULL,0x1A0111EA397FE699ULL}};
inline constexpr Fp2 GAMMA15 = {{{0x9B18FAE980078116ULL,0xC63A3E6E257F8732ULL,0x8BEADF4D8E9C0566ULL,0xF39816240C0B8FEEULL,0xDF47FA6B48B1E045ULL,0x05B2CFD9013A5FD8ULL}},
                                {{0x1EE605167FF82995ULL,0x5871C1908BD478CDULL,0xDB45F3536814F0BDULL,0x70DF3560E77982D0ULL,0x6BD3AD4AFA99CC91ULL,0x144E4211384586C1ULL}}};
inline constexpr Fp  GAMMA21 = {{0x2E01FFFFFFFEFFFFULL,0xDE17D813620A0002ULL,0xDDB3A93BE6F89688ULL,0xBA69C6076A0F77EAULL,0x5F19672FDF76CE51ULL,0}};
inline constexpr Fp  GAMMA22 = {{0x2E01FFFFFFFEFFFEULL,0xDE17D813620A0002ULL,0xDDB3A93BE6F89688ULL,0xBA69C6076A0F77EAULL,0x5F19672FDF76CE51ULL,0}};
inline constexpr Fp  GAMMA23 = {{0xB9FEFFFFFFFFAAAAULL,0x1EABFFFEB153FFFFULL,0x6730D2A0F6B0F624ULL,0x64774B84F38512BFULL,0x4B1BA7B6434BACD7ULL,0x1A0111EA397FE69AULL}};
inline constexpr Fp  GAMMA24 = {{0x8BFD00000000AAACULL,0x409427EB4F49FFFDULL,0x897D29650FB85F9BULL,0xAA0D857D89759AD4ULL,0xEC02408663D4DE85ULL,0x1A0111EA397FE699ULL}};
inline constexpr Fp  GAMMA25 = {{0x8BFD00000000AAADULL,0x409427EB4F49FFFDULL,0x897D29650FB85F9BULL,0xAA0D857D89759AD4ULL,0xEC02408663D4DE85ULL,0x1A0111EA397FE699ULL}};

// (a0+a1 w)(b0+b1 w) = (a0 b0 + (a1 b1)·v) + ((a0+a1)(b0+b1) - a0b0 - a1b1)·w
inline Fp12 fp12_mul(const Fp12& a, const Fp12& b) {
    Fp6 a0b0 = fp6_mul(a.c0, b.c0);
    Fp6 a1b1 = fp6_mul(a.c1, b.c1);
    Fp6 c0 = fp6_add(a0b0, fp6_mul_by_v(a1b1));
    Fp6 c1 = fp6_sub(fp6_sub(fp6_mul(fp6_add(a.c0,a.c1), fp6_add(b.c0,b.c1)), a0b0), a1b1);
    return { c0, c1 };
}

inline Fp12 fp12_sqr(const Fp12& a) {
    Fp6 a0a1 = fp6_mul(a.c0, a.c1);
    Fp6 a1v  = fp6_mul_by_v(a.c1);
    Fp6 a0a1v = fp6_mul_by_v(a0a1);
    Fp6 c1 = fp6_dbl(a0a1);
    Fp6 c0 = fp6_add(fp6_add(fp6_mul(fp6_sub(a.c0,a.c1), fp6_sub(a.c0,a1v)), a0a1), a0a1v);
    return { c0, c1 };
}

inline Fp12 fp12_inv(const Fp12& a) {
    Fp6 denom = fp6_sub(fp6_sqr(a.c0), fp6_mul_by_v(fp6_sqr(a.c1)));
    Fp6 di = fp6_inv(denom);
    return { fp6_mul(a.c0, di), fp6_neg(fp6_mul(a.c1, di)) };
}

inline Fp12 fp12_conjugate(const Fp12& a) { return { a.c0, fp6_neg(a.c1) }; }

// Sparse mul by b = 1 + (b22·v + b23·v²)·w  (Miller-loop line accumulation).
inline Fp12 fp12_sparse_mul(const Fp12& a, const Fp2& b22, const Fp2& b23) {
    Fp2 b23u = nr(b23);                                   // b23·(1+u)
    Fp6 c0 = fp6_add(fp6_sparse_mulc(a.c1, b23u, b22), a.c0);
    Fp6 c1 = fp6_add(fp6_sparse_mulb(a.c0, b22, b23), a.c1);
    return { c0, c1 };
}

// x^p
inline Fp12 fp12_frobenius1(const Fp12& a) {
    Fp12 r;
    r.c0.c0 = fp2_conjugate(a.c0.c0);
    r.c0.c1 = fp2_mul(fp2_conjugate(a.c0.c1), GAMMA12);
    r.c0.c2 = fp2_scalar_mul(fp2_conjugate(a.c0.c2), GAMMA14);
    r.c1.c0 = fp2_mul(fp2_conjugate(a.c1.c0), GAMMA11);
    r.c1.c1 = fp2_mul(fp2_conjugate(a.c1.c1), GAMMA13);
    r.c1.c2 = fp2_mul(fp2_conjugate(a.c1.c2), GAMMA15);
    return r;
}
// x^{p²}
inline Fp12 fp12_frobenius2(const Fp12& a) {
    Fp12 r;
    r.c0.c0 = a.c0.c0;
    r.c0.c1 = fp2_scalar_mul(a.c0.c1, GAMMA22);
    r.c0.c2 = fp2_scalar_mul(a.c0.c2, GAMMA24);
    r.c1.c0 = fp2_scalar_mul(a.c1.c0, GAMMA21);
    r.c1.c1 = fp2_scalar_mul(a.c1.c1, GAMMA23);
    r.c1.c2 = fp2_scalar_mul(a.c1.c2, GAMMA25);
    return r;
}

} // namespace zeg::bls

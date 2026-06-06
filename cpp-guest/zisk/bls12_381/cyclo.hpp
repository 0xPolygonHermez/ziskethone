// cyclo.hpp — BLS12-381 cyclotomic subgroup ops + final exponentiation.
//
// Layer 6a of the KZG port. Compressed squaring in GΦ6(p²) (Karabina) drives the
// exponentiations by the curve parameter X used in the hard part of the final
// exponentiation f^((p¹²-1)/r). Built on Fp12/Fp2; backend-agnostic.
// Faithful to zisklib/lib/bls12_381/{cyclotomic,final_exp}.rs.

#pragma once

#include "fp12.hpp"

namespace zeg::bls {

// Compressed cyclotomic element [a2,a3,a4,a5] ∈ Fp2⁴.
struct CycloC { Fp2 a2, a3, a4, a5; };

inline constexpr Fp2 FP2_TWO_PLUS_U = {{{2,0,0,0,0,0}}, {{1,0,0,0,0,0}}};  // 2+u

// a = (a0 + a4·v + a3·v²) + (a2 + a1·v + a5·v²)·w
inline CycloC cyclo_compress(const Fp12& a) {
    return { a.c1.c0, a.c0.c2, a.c0.c1, a.c1.c2 };      // a2,a3,a4,a5
}

inline Fp12 cyclo_decompress(const CycloC& c) {
    const Fp2& a2 = c.a2; const Fp2& a3 = c.a3; const Fp2& a4 = c.a4; const Fp2& a5 = c.a5;
    Fp three{{3,0,0,0,0,0}}, four{{4,0,0,0,0,0}};
    Fp2 a0, a1;
    if (fp2_is_zero(a2)) {
        // a1 = (2·a4·a5)/a3
        a1 = fp2_mul(fp2_dbl(fp2_mul(a4, a5)), fp2_inv(a3));
        // a0 = (2·a1² - 3·a3·a4)(1+u) + 1
        Fp2 t = fp2_sub(fp2_dbl(fp2_sqr(a1)), fp2_scalar_mul(fp2_mul(a3, a4), three));
        a0 = fp2_add(fp2_mul_by_nonresidue(t), FP2_ONE);
    } else {
        // a1 = (a5²·(1+u) + 3·a4² - 2·a3)/(4·a2)
        Fp2 a2inv = fp2_inv(fp2_scalar_mul(a2, four));
        Fp2 t = fp2_mul_by_nonresidue(fp2_sqr(a5));
        t = fp2_add(t, fp2_scalar_mul(fp2_sqr(a4), three));
        t = fp2_sub(t, fp2_dbl(a3));
        a1 = fp2_mul(t, a2inv);
        // a0 = (2·a1² + a2·a5 - 3·a3·a4)(1+u) + 1
        Fp2 u = fp2_dbl(fp2_sqr(a1));
        u = fp2_add(u, fp2_mul(a2, a5));
        u = fp2_sub(u, fp2_scalar_mul(fp2_mul(a3, a4), three));
        a0 = fp2_add(fp2_mul_by_nonresidue(u), FP2_ONE);
    }
    Fp12 r;
    r.c0.c0 = a0; r.c0.c1 = a4; r.c0.c2 = a3;
    r.c1.c0 = a2; r.c1.c1 = a1; r.c1.c2 = a5;
    return r;
}

inline CycloC cyclo_square(const CycloC& c) {
    const Fp2& a2 = c.a2; const Fp2& a3 = c.a3; const Fp2& a4 = c.a4; const Fp2& a5 = c.a5;
    Fp three{{3,0,0,0,0,0}};
    Fp2 B23 = fp2_mul(a2, a3), B45 = fp2_mul(a4, a5);
    Fp2 A23 = fp2_mul(fp2_add(a2, a3), fp2_add(a2, fp2_mul_by_nonresidue(a3)));
    Fp2 A45 = fp2_mul(fp2_add(a4, a5), fp2_add(a4, fp2_mul_by_nonresidue(a5)));
    Fp2 b2 = fp2_dbl(fp2_add(a2, fp2_scalar_mul(fp2_mul_by_nonresidue(B45), three)));
    Fp2 b3 = fp2_sub(fp2_scalar_mul(fp2_sub(A45, fp2_mul(B45, FP2_TWO_PLUS_U)), three), fp2_dbl(a3));
    Fp2 b4 = fp2_sub(fp2_scalar_mul(fp2_sub(A23, fp2_mul(B23, FP2_TWO_PLUS_U)), three), fp2_dbl(a4));
    Fp2 b5 = fp2_dbl(fp2_add(a5, fp2_scalar_mul(B23, three)));
    return { b2, b3, b4, b5 };
}

// a^e in the cyclotomic subgroup; `bits` is little-endian (bit 0 first).
inline Fp12 cyclo_exp(const Fp12& a, const uint8_t* bits, int n) {
    if (fp12_is_zero(a)) return FP12_ZERO;
    Fp12 result = FP12_ONE;
    CycloC comp = cyclo_compress(a);
    for (int i = 0; i < n; ++i) {
        if (bits[i]) result = fp12_mul(result, cyclo_decompress(comp));
        comp = cyclo_square(comp);
    }
    return result;
}

// Curve-parameter exponents |X|, |X|+1, (|X|+1)/3 as little-endian bit strings.
inline const uint8_t* X_ABS_BIN_LE() {
    static const uint8_t b[64] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,1,0,0,1,0,1,1};
    return b;
}
inline const uint8_t* XONE_ABS_BIN_LE() {
    static const uint8_t b[64] = {
        1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,1,0,0,1,0,1,1};
    return b;
}
inline const uint8_t* XDIV3_ABS_BIN_LE() {
    static const uint8_t b[63] = {
        1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,
        1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,1};
    return b;
}
inline Fp12 exp_by_x_cyclo(const Fp12& a)    { return cyclo_exp(a, X_ABS_BIN_LE(), 64); }
inline Fp12 exp_by_xone_cyclo(const Fp12& a) { return cyclo_exp(a, XONE_ABS_BIN_LE(), 64); }
inline Fp12 exp_by_xdiv3_cyclo(const Fp12& a){ return cyclo_exp(a, XDIV3_ABS_BIN_LE(), 63); }

// f^((p¹²-1)/r). X is negative, so f^x = conjugate(f)^|x| (handled here).
inline Fp12 final_exp(const Fp12& f) {
    // Easy part: f^(p^6-1)(p^2+1)
    Fp12 easy1 = fp12_mul(fp12_conjugate(f), fp12_inv(f));        // f^(p^6-1)
    Fp12 m = fp12_mul(fp12_frobenius2(easy1), easy1);            // ^(p²+1)
    // Hard part: (p⁴-p²+1)/r
    Fp12 t = exp_by_xdiv3_cyclo(m);
    t = exp_by_xone_cyclo(t);
    Fp12 f1 = fp12_frobenius1(t);
    Fp12 f2 = exp_by_x_cyclo(fp12_conjugate(t));
    Fp12 ff = fp12_mul(f1, f2);
    Fp12 g1 = exp_by_x_cyclo(exp_by_x_cyclo(ff));
    Fp12 g2 = fp12_frobenius2(ff);
    Fp12 g3 = fp12_conjugate(ff);
    Fp12 res = fp12_mul(fp12_mul(fp12_mul(g1, g2), g3), m);
    return res;
}

} // namespace zeg::bls

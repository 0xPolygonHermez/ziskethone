// fp12.hpp — BN254 dodecic extension Fp12 = Fp6[w]/(w² - v).
//
// Layer 3b of the BN254 port. Fp12 = c0 + c1·w (two Fp6, 48 u64). Built on Fp6,
// so backend-agnostic. Frobenius operators use the auto-extracted γ constants
// (γ1x/γ3x ∈ Fp2 with conjugation; γ2x ∈ Fp scalar, no conjugation). Faithful to
// zisklib/lib/bn254/fp12.rs.

#pragma once

#include "fp6.hpp"
#include "constants.hpp"

namespace zeg::bn {

struct Fp12 { Fp6 c0, c1; };  // c0 + c1·w

inline constexpr Fp12 FP12_ZERO = {FP6_ZERO, FP6_ZERO};
inline constexpr Fp12 FP12_ONE  = {FP6_ONE,  FP6_ZERO};

inline bool fp12_eq(const Fp12& a, const Fp12& b) { return fp6_eq(a.c0,b.c0) && fp6_eq(a.c1,b.c1); }
inline bool fp12_is_one(const Fp12& a) { return fp12_eq(a, FP12_ONE); }

inline Fp12 fp12_add(const Fp12& a, const Fp12& b) { return { fp6_add(a.c0,b.c0), fp6_add(a.c1,b.c1) }; }
inline Fp12 fp12_sub(const Fp12& a, const Fp12& b) { return { fp6_sub(a.c0,b.c0), fp6_sub(a.c1,b.c1) }; }

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
    Fp6 c0 = fp6_mul(fp6_sub(a.c0,a.c1), fp6_sub(a.c0,a1v));
    c0 = fp6_add(fp6_add(c0, a0a1), a0a1v);
    Fp6 c1 = fp6_dbl(a0a1);
    return { c0, c1 };
}

inline Fp12 fp12_inv(const Fp12& a) {
    Fp6 t = fp6_inv(fp6_sub(fp6_sqr(a.c0), fp6_mul_by_v(fp6_sqr(a.c1))));
    return { fp6_mul(a.c0, t), fp6_neg(fp6_mul(a.c1, t)) };
}

inline Fp12 fp12_conjugate(const Fp12& a) { return { a.c0, fp6_neg(a.c1) }; }

// p-power Frobenius: conjugate each Fp2 then multiply by γ1x (Fp2).
inline Fp12 fp12_frobenius1(const Fp12& a) {
    Fp6 c0{ fp2_conjugate(a.c0.c0),
            fp2_mul(fp2_conjugate(a.c0.c1), FROB_G12),
            fp2_mul(fp2_conjugate(a.c0.c2), FROB_G14) };
    Fp6 c1{ fp2_mul(fp2_conjugate(a.c1.c0), FROB_G11),
            fp2_mul(fp2_conjugate(a.c1.c1), FROB_G13),
            fp2_mul(fp2_conjugate(a.c1.c2), FROB_G15) };
    return { c0, c1 };
}
// p²-power Frobenius: no conjugation; multiply by γ2x (Fp scalar).
inline Fp12 fp12_frobenius2(const Fp12& a) {
    Fp6 c0{ a.c0.c0,
            fp2_scalar_mul(a.c0.c1, FROB_G22),
            fp2_scalar_mul(a.c0.c2, FROB_G24) };
    Fp6 c1{ fp2_scalar_mul(a.c1.c0, FROB_G21),
            fp2_scalar_mul(a.c1.c1, FROB_G23),
            fp2_scalar_mul(a.c1.c2, FROB_G25) };
    return { c0, c1 };
}
// p³-power Frobenius: conjugate then multiply by γ3x (Fp2).
inline Fp12 fp12_frobenius3(const Fp12& a) {
    Fp6 c0{ fp2_conjugate(a.c0.c0),
            fp2_mul(fp2_conjugate(a.c0.c1), FROB_G32),
            fp2_mul(fp2_conjugate(a.c0.c2), FROB_G34) };
    Fp6 c1{ fp2_mul(fp2_conjugate(a.c1.c0), FROB_G31),
            fp2_mul(fp2_conjugate(a.c1.c1), FROB_G33),
            fp2_mul(fp2_conjugate(a.c1.c2), FROB_G35) };
    return { c0, c1 };
}

// sparse Fp12 mul by (1 + (b21 + b22·v)·w) — line value from the Miller loop.
// c0 = a0 + a1·(b21·v + b22·v²) ; c1 = a1 + a0·(b21 + b22·v).
inline Fp12 fp12_sparse_mul(const Fp12& a, const Fp2& b21, const Fp2& b22) {
    Fp6 c0 = fp6_add(fp6_mul_b12(a.c1, b21, b22), a.c0);
    Fp6 c1 = fp6_add(fp6_mul_b01(a.c0, b21, b22), a.c1);
    return { c0, c1 };
}

} // namespace zeg::bn

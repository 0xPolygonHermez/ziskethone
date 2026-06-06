// g2.hpp — BN254 G2 on the twist E': y² = x³ + 3/(9+u) over Fp2.
//
// Layer 5 of the BN254 port. Affine points G2 = (x, y) ∈ Fp2² (16 u64). All ops
// are software Fp2 affine formulas (no G2 curve precompile); the Fp2 layer carries
// the ZEG_ZISK backend, so this file is backend-agnostic. Subgroup membership uses
// the untwist-Frobenius-twist ψ and the eprint 2022/348 relation. Faithful to
// zisklib/lib/bn254/twist.rs.

#pragma once

#include "fp2.hpp"
#include "constants.hpp"

namespace zeg::bn {

struct G2 { Fp2 x, y; };  // affine twist point; (0,0) = point at infinity

inline constexpr G2 G2_IDENTITY = {FP2_ZERO, FP2_ZERO};

inline bool g2_eq(const G2& a, const G2& b) { return fp2_eq(a.x,b.x) && fp2_eq(a.y,b.y); }
inline bool g2_is_identity(const G2& p) { return fp2_is_zero(p.x) && fp2_is_zero(p.y); }
inline G2 g2_neg(const G2& p) { return { p.x, fp2_neg(p.y) }; }
inline bool g2_in_field(const G2& p) {
    return fp_lt(p.x.c0,FP_P) && fp_lt(p.x.c1,FP_P) && fp_lt(p.y.c0,FP_P) && fp_lt(p.y.c1,FP_P);
}

// on twist: y² == x³ + 3/(9+u)
inline bool g2_is_on_curve(const G2& p) {
    Fp2 rhs = fp2_add(fp2_mul(fp2_sqr(p.x), p.x), ETWISTED_B);
    return fp2_eq(fp2_sqr(p.y), rhs);
}

// raw affine add, requires x1 != x2.
inline G2 g2_add_raw(const G2& a, const G2& b) {
    Fp2 lam = fp2_mul(fp2_sub(b.y, a.y), fp2_inv(fp2_sub(b.x, a.x)));
    Fp2 x3 = fp2_sub(fp2_sub(fp2_sqr(lam), a.x), b.x);
    Fp2 y3 = fp2_sub(fp2_mul(lam, fp2_sub(a.x, x3)), a.y);
    return { x3, y3 };
}
// doubling, requires y != 0. λ = 3x²/(2y).
inline G2 g2_dbl(const G2& p) {
    Fp2 lam = fp2_scalar_mul(fp2_inv(fp2_dbl(p.y)), E_B);   // 3/(2y)
    lam = fp2_mul(fp2_mul(lam, p.x), p.x);                  // ·x·x
    Fp2 x3 = fp2_sub(fp2_sub(fp2_sqr(lam), p.x), p.x);
    Fp2 y3 = fp2_sub(fp2_mul(lam, fp2_sub(p.x, x3)), p.y);
    return { x3, y3 };
}
// complete add (handles ∞, doubling, opposite).
inline G2 g2_add(const G2& a, const G2& b) {
    if (g2_is_identity(a)) return b;
    if (g2_is_identity(b)) return a;
    if (fp2_eq(a.x, b.x)) {
        if (fp2_eq(a.y, b.y)) return g2_dbl(a);
        return G2_IDENTITY;
    }
    return g2_add_raw(a, b);
}
inline G2 g2_sub(const G2& a, const G2& b) { return g2_add(a, g2_neg(b)); }

// [x]·P, x = 4965661367192848881 (BN curve parameter), MSB-first double-and-add.
inline G2 g2_scalar_mul_by_x(const G2& p) {
    static const uint8_t X_BIN_BE[63] = {
        1,0,0,0,1,0,0,1,1,1,0,1,0,0,1,1,0,0,1,0,0,1,0,1,0,1,1,0,1,0,
        0,0,1,0,0,1,0,1,0,0,1,1,0,1,0,0,1,0,0,0,0,1,0,0,1,1,1,1,1,0,
        0,0,1 };
    G2 q = p;
    for (int i = 1; i < 63; ++i) {
        q = g2_dbl(q);
        if (X_BIN_BE[i]) q = g2_add(q, p);
    }
    return q;
}

// ψ: untwist-Frobenius-twist endomorphism (x,y) → (γ12·x̄, γ13·ȳ).
inline G2 g2_utf(const G2& p) {
    return { fp2_mul(FROB_G12, fp2_conjugate(p.x)), fp2_mul(FROB_G13, fp2_conjugate(p.y)) };
}

// subgroup test: (x+1)Q + ψ(xQ) + ψ²(xQ) == ψ³((2x)Q)  (eprint 2022/348).
inline bool g2_is_on_subgroup(const G2& p) {
    if (g2_is_identity(p)) return true;
    G2 xp = g2_scalar_mul_by_x(p);
    G2 lhs = g2_add(g2_add(p, xp), g2_add(g2_utf(xp), g2_utf(g2_utf(xp))));
    G2 rhs = g2_utf(g2_utf(g2_utf(g2_dbl(xp))));
    return g2_eq(lhs, rhs);
}

} // namespace zeg::bn

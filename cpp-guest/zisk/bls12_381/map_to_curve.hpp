// map_to_curve.hpp — BLS12-381 map-to-curve for EIP-2537 map_fp_to_g1 / map_fp2_to_g2.
//
// Simplified SWU onto the isogenous curve E', the isogeny map E'→E (11-iso for
// G1, 3-iso for G2), then cofactor clearing (scalar [h]P for G1; the ψ-based
// Budroni–Pintore map for G2). Faithful to zisklib map_to_curve.rs / twist.rs;
// the large isogeny/SWU constant tables live in map_constants.hpp (auto-extracted).

#pragma once

#include "map_constants.hpp"
#include "g1.hpp"
#include "g2.hpp"
#include "g2_subgroup.hpp"   // g2_utf = ψ endomorphism

namespace zeg::bls {

// ---- Horner polynomial evaluation -------------------------------------------
inline Fp eval_poly_fp(const Fp* c, int n, const Fp& x) {
    Fp r = c[n-1];
    for (int i = n-2; i >= 0; --i) { r = fp_mul(r, x); r = fp_add(r, c[i]); }
    return r;
}
inline Fp2 eval_poly_fp2(const Fp2* c, int n, const Fp2& x) {
    Fp2 r = c[n-1];
    for (int i = n-2; i >= 0; --i) { r = fp2_mul(r, x); r = fp2_add(r, c[i]); }
    return r;
}

// ---- E' curve equation y² = x³ + A'x + B' -----------------------------------
inline Fp  y2_iso_g1(const Fp&  x) { return fp_add(fp_add(fp_mul(fp_sqr(x), x), fp_mul(ISO_A_G1, x)), ISO_B_G1); }
inline Fp2 y2_iso_g2(const Fp2& x) { return fp2_add(fp2_add(fp2_mul(fp2_sqr(x), x), fp2_mul(ISO_A_G2, x)), ISO_B_G2); }

// ---- simplified SWU onto E' --------------------------------------------------
inline G1 swu_g1(const Fp& u) {
    Fp u2 = fp_sqr(u), u4 = fp_sqr(u2);
    Fp z_u2 = fp_mul(SWU_Z_G1, u2);
    Fp tv1 = fp_inv(fp_add(fp_mul(SWU_Z2_G1, u4), z_u2));            // inv0
    Fp neg_b_over_a = fp_mul(fp_neg(ISO_B_G1), fp_inv(ISO_A_G1));
    Fp x1 = fp_mul(neg_b_over_a, fp_add(FP_ONE, tv1));
    if (fp_is_zero(tv1)) x1 = fp_mul(ISO_B_G1, fp_inv(fp_mul(SWU_Z_G1, ISO_A_G1)));
    Fp gx1 = y2_iso_g1(x1);
    bool qr; Fp y1 = fp_sqrt(gx1, &qr);
    Fp x, y;
    if (qr) { x = x1; y = y1; }
    else {
        Fp x2 = fp_mul(z_u2, x1);
        bool qr2; Fp y2 = fp_sqrt(y2_iso_g1(x2), &qr2);
        x = x2; y = y2;
    }
    if (fp_sgn0(u) != fp_sgn0(y)) y = fp_neg(y);
    return { x, y };
}
inline G2 swu_g2(const Fp2& u) {
    Fp2 u2 = fp2_sqr(u), u4 = fp2_sqr(u2);
    Fp2 z_u2 = fp2_mul(SWU_Z_G2, u2);
    Fp2 z2 = fp2_sqr(SWU_Z_G2);
    Fp2 tv1 = fp2_inv(fp2_add(fp2_mul(z2, u4), z_u2));              // inv0
    Fp2 neg_b_over_a = fp2_mul(fp2_neg(ISO_B_G2), fp2_inv(ISO_A_G2));
    Fp2 x1 = fp2_mul(neg_b_over_a, fp2_add(FP2_ONE, tv1));
    if (fp2_is_zero(tv1)) x1 = fp2_mul(ISO_B_G2, fp2_inv(fp2_mul(SWU_Z_G2, ISO_A_G2)));
    Fp2 gx1 = y2_iso_g2(x1);
    bool qr; Fp2 y1 = fp2_sqrt(gx1, &qr);
    Fp2 x, y;
    if (qr) { x = x1; y = y1; }
    else {
        Fp2 x2 = fp2_mul(z_u2, x1);
        bool qr2; Fp2 y2 = fp2_sqrt(y2_iso_g2(x2), &qr2);
        x = x2; y = y2;
    }
    if (fp2_sgn0(u) != fp2_sgn0(y)) y = fp2_neg(y);
    return { x, y };
}

// ---- isogeny maps E'→E -------------------------------------------------------
inline G1 isogeny_g1(const G1& p) {
    Fp xn = eval_poly_fp(ISO_X_NUM_G1, 12, p.x);
    Fp xd = eval_poly_fp(ISO_X_DEN_G1, 11, p.x);
    Fp xo = fp_mul(xn, fp_inv(xd));
    Fp yn = eval_poly_fp(ISO_Y_NUM_G1, 16, p.x);
    Fp yd = eval_poly_fp(ISO_Y_DEN_G1, 16, p.x);
    Fp yo = fp_mul(p.y, fp_mul(yn, fp_inv(yd)));
    return { xo, yo };
}
inline G2 isogeny_g2(const G2& p) {
    Fp2 xn = eval_poly_fp2(ISO_X_NUM_G2, 4, p.x);
    Fp2 xd = eval_poly_fp2(ISO_X_DEN_G2, 3, p.x);
    Fp2 xo = fp2_mul(xn, fp2_inv(xd));
    Fp2 yn = eval_poly_fp2(ISO_Y_NUM_G2, 4, p.x);
    Fp2 yd = eval_poly_fp2(ISO_Y_DEN_G2, 4, p.x);
    Fp2 yo = fp2_mul(p.y, fp2_mul(yn, fp2_inv(yd)));
    return { xo, yo };
}

// ---- G2 cofactor clearing (Budroni–Pintore, ψ = g2_utf) ---------------------
// h_eff·P = [x²−x−1]P + [x−1]ψ(P) + ψ²(2P)  (x = curve param, negative); we
// follow zisklib's exact step sequence so it matches the emulator.
inline G2 g2_clear_cofactor(const G2& p) {
    constexpr uint64_t ABS_X[4] = {0xD201000000010000ULL, 0, 0, 0};
    G2 t1 = g2_neg(g2_scalar_mul(p, ABS_X));   // [x]P
    G2 t2 = g2_utf(p);                          // ψ(P)
    G2 t3 = g2_utf(g2_utf(g2_dbl(p)));          // ψ²(2P)
    t3 = g2_sub_complete(t3, t2);               // ψ²(2P) − ψ(P)
    t2 = g2_add_complete(t1, t2);               // [x]P + ψ(P)
    t2 = g2_neg(g2_scalar_mul(t2, ABS_X));      // [x]([x]P + ψ(P))
    t3 = g2_add_complete(t3, t2);
    t3 = g2_sub_complete(t3, t1);
    return g2_sub_complete(t3, p);
}

// ---- full map-to-curve (input already validated in-field) -------------------
inline G1 map_to_curve_g1(const Fp&  u) { return g1_scalar_mul(isogeny_g1(swu_g1(u)), COFACTOR_G1); }
inline G2 map_to_curve_g2(const Fp2& u) { return g2_clear_cofactor(isogeny_g2(swu_g2(u))); }

} // namespace zeg::bls

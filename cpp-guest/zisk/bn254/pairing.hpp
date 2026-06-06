// pairing.hpp — BN254 optimal-Ate pairing (Miller loop + final exp).
//
// Layer 6 of the BN254 port. Miller loop over 6X+2 with hinted line coefficients
// (λ,μ) from the twist line fcalls (dbl id 9, add id 8), verified in-circuit via
// is_tangent / is_line; lines evaluated at P and folded in with the sparse Fp12
// mul. Final exponentiation: easy part (p⁶-1)(p²+1) then the hard part
// (p⁴-p²+1)/r built from m^x (ordinary Fp12 exp by the BN parameter) + Frobenius.
// Faithful to zisklib/lib/bn254/{miller_loop,final_exp,cyclotomic}.rs.

#pragma once

#include "g1.hpp"
#include "g2.hpp"
#include "fp12.hpp"

namespace zeg::bn {

struct LineCoeffs { Fp2 lambda, mu; };  // 16 contiguous u64 (λ.c0,λ.c1,μ.c0,μ.c1)

// pseudo-binary 6X+2 loop (65 entries; iterate from index 1).
inline const int8_t* LOOP_6XP2() {
    static const int8_t L[65] = {
        1, 1, 0, 1, 0, 0,-1, 0, 1, 1, 0, 0, 0,-1, 0, 0, 1, 1, 0, 0,-1, 0, 0, 0, 0, 0, 1, 0, 0,-1,
        0, 0, 1, 1, 1, 0, 0, 0, 0,-1, 0, 1, 0, 0,-1, 0, 1, 1, 0, 0, 1, 0, 0,-1, 1, 0, 0,-1, 0, 1,
        0, 1, 0, 0, 0 };
    return L;
}

// ===========================================================================
// Backend: the twist line-coefficient fcalls (G2 point = 16 u64 → port 0x8F5).
// ===========================================================================
#if defined(ZEG_ZISK)
inline uint64_t pl_get() { uint64_t v; asm volatile("csrr %0, 0xFFE" : "=r"(v)); return v; }
inline LineCoeffs twist_dbl_line(const G2& r) {
    asm volatile("csrs 0x8F5, %0" : : "r"(reinterpret_cast<const uint64_t*>(&r)) : "memory");
    asm volatile("csrwi 0x8C0, 9" : : : "memory");  // FCALL_BN254_TWIST_DBL_LINE_COEFFS_ID
    LineCoeffs lc; uint64_t* o = reinterpret_cast<uint64_t*>(&lc);
    for (int i = 0; i < 16; ++i) o[i] = pl_get();
    return lc;
}
inline LineCoeffs twist_add_line(const G2& r, const G2& q) {
    asm volatile("csrs 0x8F5, %0" : : "r"(reinterpret_cast<const uint64_t*>(&r)) : "memory");
    asm volatile("csrs 0x8F5, %0" : : "r"(reinterpret_cast<const uint64_t*>(&q)) : "memory");
    asm volatile("csrwi 0x8C0, 8" : : : "memory");  // FCALL_BN254_TWIST_ADD_LINE_COEFFS_ID
    LineCoeffs lc; uint64_t* o = reinterpret_cast<uint64_t*>(&lc);
    for (int i = 0; i < 16; ++i) o[i] = pl_get();
    return lc;
}
#else
inline LineCoeffs twist_dbl_line(const G2& r) {  // λ=3x²/2y, μ=y-λx
    Fp2 lam = fp2_mul(fp2_scalar_mul(fp2_sqr(r.x), Fp{{3,0,0,0}}), fp2_inv(fp2_dbl(r.y)));
    return { lam, fp2_sub(r.y, fp2_mul(lam, r.x)) };
}
inline LineCoeffs twist_add_line(const G2& r, const G2& q) {  // λ=(qy-ry)/(qx-rx), μ=ry-λrx
    Fp2 lam = fp2_mul(fp2_sub(q.y, r.y), fp2_inv(fp2_sub(q.x, r.x)));
    return { lam, fp2_sub(r.y, fp2_mul(lam, r.x)) };
}
#endif

// ---- line verification (hint must be exact) --------------------------------
inline bool line_check(const G2& q, const Fp2& lam, const Fp2& mu) {  // y == λx + μ
    return fp2_eq(q.y, fp2_add(fp2_mul(lam, q.x), mu));
}
inline bool is_tangent(const G2& q, const Fp2& lam, const Fp2& mu) {  // + 2λy == 3x²
    Fp2 lhs = fp2_dbl(fp2_mul(lam, q.y));
    Fp2 rhs = fp2_scalar_mul(fp2_sqr(q.x), Fp{{3,0,0,0}});
    return line_check(q, lam, mu) && fp2_eq(lhs, rhs);
}
inline bool is_line(const G2& q1, const G2& q2, const Fp2& lam, const Fp2& mu) {
    return line_check(q1, lam, mu) && line_check(q2, lam, mu);
}

// ---- point update from hinted (λ,μ) ----------------------------------------
inline G2 dbl_with_hints(const G2& r, const Fp2& lam, const Fp2& mu) {  // x3=λ²-2x
    Fp2 x3 = fp2_sub(fp2_sqr(lam), fp2_dbl(r.x));
    return { x3, fp2_neg(fp2_add(mu, fp2_mul(lam, x3))) };
}
inline G2 add_with_hints(const G2& r, const G2& q, const Fp2& lam, const Fp2& mu) {  // x3=λ²-rx-qx
    Fp2 x3 = fp2_sub(fp2_sub(fp2_sqr(lam), r.x), q.x);
    return { x3, fp2_neg(fp2_add(mu, fp2_mul(lam, x3))) };
}

// line value at P=(xp', yp'): (b21, b22) = (λ·xp', -μ·yp').
inline void line_eval(const Fp2& lam, const Fp2& mu, const Fp& xpp, const Fp& ypp, Fp2* b21, Fp2* b22) {
    *b21 = fp2_scalar_mul(lam, xpp);
    *b22 = fp2_scalar_mul(mu, fp_neg(ypp));
}

inline Fp12 miller_loop(const G1& p, const G2& q) {
    Fp ypp = fp_inv(p.y);                       // yp' = 1/yp
    Fp xpp = fp_mul(fp_neg(p.x), ypp);          // xp' = -xp/yp
    const int8_t* L = LOOP_6XP2();
    G2 r = q;
    Fp12 f = FP12_ONE;
    Fp2 b21, b22;
    for (int i = 1; i < 65; ++i) {
        LineCoeffs lc = twist_dbl_line(r);
        if (!is_tangent(r, lc.lambda, lc.mu)) { for (;;) {} }
        f = fp12_sqr(f);
        line_eval(lc.lambda, lc.mu, xpp, ypp, &b21, &b22);
        f = fp12_sparse_mul(f, b21, b22);
        r = dbl_with_hints(r, lc.lambda, lc.mu);
        if (L[i] * L[i] == 1) {
            G2 qp = (L[i] == 1) ? q : g2_neg(q);
            LineCoeffs la = twist_add_line(r, qp);
            if (!is_line(r, qp, la.lambda, la.mu)) { for (;;) {} }
            line_eval(la.lambda, la.mu, xpp, ypp, &b21, &b22);
            f = fp12_sparse_mul(f, b21, b22);
            r = add_with_hints(r, qp, la.lambda, la.mu);
        }
    }
    // final two lines: utf(q) and -utf(utf(q))
    G2 qf = g2_utf(q);
    { LineCoeffs la = twist_add_line(r, qf);
      if (!is_line(r, qf, la.lambda, la.mu)) { for (;;) {} }
      line_eval(la.lambda, la.mu, xpp, ypp, &b21, &b22);
      f = fp12_sparse_mul(f, b21, b22);
      r = add_with_hints(r, qf, la.lambda, la.mu); }
    G2 qf2 = g2_neg(g2_utf(qf));
    { LineCoeffs la = twist_add_line(r, qf2);
      if (!is_line(r, qf2, la.lambda, la.mu)) { for (;;) {} }
      line_eval(la.lambda, la.mu, xpp, ypp, &b21, &b22);
      f = fp12_sparse_mul(f, b21, b22); }
    return f;
}

// m^x, x = 4965661367192848881 (BN parameter), MSB-first (same bits as g2).
inline Fp12 exp_by_x(const Fp12& a) {
    static const uint8_t X[63] = {
        1,0,0,0,1,0,0,1,1,1,0,1,0,0,1,1,0,0,1,0,0,1,0,1,0,1,1,0,1,0,
        0,0,1,0,0,1,0,1,0,0,1,1,0,1,0,0,1,0,0,0,0,1,0,0,1,1,1,1,1,0,
        0,0,1 };
    Fp12 r = a;
    for (int i = 1; i < 63; ++i) { r = fp12_sqr(r); if (X[i]) r = fp12_mul(r, a); }
    return r;
}

inline Fp12 final_exp(const Fp12& f) {
    // easy part: (p⁶-1)(p²+1)
    Fp12 easy1 = fp12_mul(fp12_conjugate(f), fp12_inv(f));      // f^(p⁶-1)
    Fp12 m = fp12_mul(fp12_frobenius2(easy1), easy1);           // ^(p²+1)
    // hard part: (p⁴-p²+1)/r  (Fuentes-Castaneda style addition chain)
    Fp12 mx = exp_by_x(m), mxx = exp_by_x(mx), mxxx = exp_by_x(mxx);
    Fp12 mp = fp12_frobenius1(m), mpp = fp12_frobenius2(m), mppp = fp12_frobenius3(m);
    Fp12 mxp = fp12_frobenius1(mx), mxxp = fp12_frobenius1(mxx), mxxxp = fp12_frobenius1(mxxx);
    Fp12 mxxpp = fp12_frobenius2(mxx);
    Fp12 y1 = fp12_mul(fp12_mul(mp, mpp), mppp);
    Fp12 y2 = fp12_conjugate(m);
    Fp12 y4 = fp12_conjugate(mxp);
    Fp12 y5 = fp12_conjugate(fp12_mul(mx, mxxp));
    Fp12 y6 = fp12_conjugate(mxx);
    Fp12 y7 = fp12_conjugate(fp12_mul(mxxx, mxxxp));
    Fp12 t11 = fp12_mul(fp12_mul(fp12_sqr(y7), y5), y6);
    Fp12 t21 = fp12_mul(fp12_mul(t11, y4), y6);
    Fp12 t12 = fp12_mul(t11, mxxpp);                            // y3 = (m^x²)^p²
    Fp12 t22 = fp12_mul(fp12_sqr(t21), t12);
    Fp12 t23 = fp12_sqr(t22);
    Fp12 t24 = fp12_mul(t23, y1);
    Fp12 t13 = fp12_mul(t23, y2);
    Fp12 t14 = fp12_mul(fp12_sqr(t13), t24);
    return t14;
}

inline Fp12 pairing(const G1& p, const G2& q) { return final_exp(miller_loop(p, q)); }

} // namespace zeg::bn

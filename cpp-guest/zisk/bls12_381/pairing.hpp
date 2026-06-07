// pairing.hpp — BLS12-381 optimal Ate pairing (Miller loop + final exp).
//
// Layer 6b of the KZG port. The Miller loop hints each line's coefficients
// (λ,μ) — via the twist line-coeff fcalls (ids 14/15) on ZisK, computed
// directly on host — then verifies them (point-on-line + tangent) and uses them
// for the line evaluation and the r-update. Faithful to
// zisklib/lib/bls12_381/{miller_loop,pairing}.rs.

#pragma once

#include "g1.hpp"
#include "g2.hpp"
#include "cyclo.hpp"

namespace zeg::bls {

// 1/(1+u) in Fp2 (zisklib EXT_U_INV).
inline constexpr Fp2 EXT_U_INV = {
    {{0xDCFF7FFFFFFFD556ULL,0x0F55FFFF58A9FFFFULL,0xB39869507B587B12ULL,0xB23BA5C279C2895FULL,0x258DD3DB21A5D66BULL,0x0D0088F51CBFF34DULL}},
    {{0xDCFF7FFFFFFFD555ULL,0x0F55FFFF58A9FFFFULL,0xB39869507B587B12ULL,0xB23BA5C279C2895FULL,0x258DD3DB21A5D66BULL,0x0D0088F51CBFF34DULL}}};

// |X| = 0xd201000000010000, big-endian bits (MSB first), 64 entries.
inline const uint8_t* X_ABS_BIN_BE() {
    static const uint8_t b[64] = {
        1,1,0,1,0,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    return b;
}

struct LineCoeffs { Fp2 lambda, mu; };

// ---- line-coefficient hints (verified by the caller) ----------------------
#if defined(ZEG_ZISK)
inline LineCoeffs twist_dbl_line(const G2& r) {
    const uint64_t* p = reinterpret_cast<const uint64_t*>(&r);   // 24 words
    asm volatile("csrs 0x8F7, %0" : : "r"(p) : "memory");        // bucket 24
    asm volatile("csrwi 0x8C0, 15" : : : "memory");             // DBL_LINE_COEFFS
    LineCoeffs lc; uint64_t* lo = reinterpret_cast<uint64_t*>(&lc);
    for (int i = 0; i < 24; ++i) lo[i] = fcall_get();           // λ(12) then μ(12)
    return lc;
}
inline LineCoeffs twist_add_line(const G2& r, const G2& q) {
    const uint64_t* pr = reinterpret_cast<const uint64_t*>(&r);
    const uint64_t* pq = reinterpret_cast<const uint64_t*>(&q);
    asm volatile("csrs 0x8F7, %0" : : "r"(pr) : "memory");
    asm volatile("csrs 0x8F7, %0" : : "r"(pq) : "memory");
    asm volatile("csrwi 0x8C0, 14" : : : "memory");            // ADD_LINE_COEFFS
    LineCoeffs lc; uint64_t* lo = reinterpret_cast<uint64_t*>(&lc);
    for (int i = 0; i < 24; ++i) lo[i] = fcall_get();
    return lc;
}
#else
inline LineCoeffs twist_dbl_line(const G2& r) {                 // λ=3x²/2y, μ=y-λx
    Fp three{{3,0,0,0,0,0}};
    Fp2 lam = fp2_mul(fp2_inv(fp2_dbl(r.y)), fp2_scalar_mul(fp2_sqr(r.x), three));
    Fp2 mu = fp2_sub(r.y, fp2_mul(lam, r.x));
    return { lam, mu };
}
inline LineCoeffs twist_add_line(const G2& r, const G2& q) {    // λ=(qy-ry)/(qx-rx), μ=ry-λrx
    Fp2 lam = fp2_mul(fp2_inv(fp2_sub(q.x, r.x)), fp2_sub(q.y, r.y));
    Fp2 mu = fp2_sub(r.y, fp2_mul(lam, r.x));
    return { lam, mu };
}
#endif

// ---- verification + line evaluation + r-update ----------------------------
inline bool line_check(const G2& q, const Fp2& lam, const Fp2& mu) {  // y == λx+μ
    return fp2_eq(q.y, fp2_add(fp2_mul(lam, q.x), mu));
}
inline bool is_tangent(const G2& q, const Fp2& lam, const Fp2& mu) {
    if (!line_check(q, lam, mu)) return false;
    Fp three{{3,0,0,0,0,0}};
    Fp2 lhs = fp2_dbl(fp2_mul(lam, q.y));               // 2λy
    Fp2 rhs = fp2_scalar_mul(fp2_sqr(q.x), three);      // 3x²
    return fp2_eq(lhs, rhs);
}
inline bool is_line(const G2& q1, const G2& q2, const Fp2& lam, const Fp2& mu) {
    return line_check(q1, lam, mu) && line_check(q2, lam, mu);
}
// line l(x,y) sparse factor: (b22, b23) = (μ·(-y'), λ·x')
inline void line_eval(const Fp2& lam, const Fp2& mu, const Fp2& xp, const Fp2& yp,
                      Fp2* b22, Fp2* b23) {
    *b22 = fp2_mul(mu, fp2_neg(yp));
    *b23 = fp2_mul(lam, xp);
}
inline G2 dbl_with_hints(const G2& r, const Fp2& lam, const Fp2& mu) {
    Fp2 x3 = fp2_sub(fp2_sqr(lam), fp2_dbl(r.x));
    Fp2 y3 = fp2_neg(fp2_add(mu, fp2_mul(lam, x3)));
    return { x3, y3 };
}
inline G2 add_with_hints(const G2& r, const G2& q, const Fp2& lam, const Fp2& mu) {
    Fp2 x3 = fp2_sub(fp2_sub(fp2_sqr(lam), r.x), q.x);
    Fp2 y3 = fp2_neg(fp2_add(mu, fp2_mul(lam, x3)));
    return { x3, y3 };
}

inline Fp12 miller_loop(const G1& p, const G2& q) {
    // xp' = (-xp/yp)/(1+u), yp' = (1/yp)/(1+u)
    Fp yi = fp_inv(p.y);
    Fp xn = fp_mul(fp_neg(p.x), yi);
    Fp2 xp = fp2_scalar_mul(EXT_U_INV, xn);
    Fp2 yp = fp2_scalar_mul(EXT_U_INV, yi);

    G2 r = q;
    Fp12 f = FP12_ONE;
    const uint8_t* X = X_ABS_BIN_BE();
    for (int i = 1; i < 64; ++i) {
        LineCoeffs lc = twist_dbl_line(r);
        if (!is_tangent(r, lc.lambda, lc.mu)) { for (;;) {} }
        f = fp12_sqr(f);
        Fp2 b22, b23; line_eval(lc.lambda, lc.mu, xp, yp, &b22, &b23);
        f = fp12_sparse_mul(f, b22, b23);
        r = dbl_with_hints(r, lc.lambda, lc.mu);
        if (X[i] == 1) {
            LineCoeffs la = twist_add_line(r, q);
            if (!is_line(r, q, la.lambda, la.mu)) { for (;;) {} }
            Fp2 c22, c23; line_eval(la.lambda, la.mu, xp, yp, &c22, &c23);
            f = fp12_sparse_mul(f, c22, c23);
            r = add_with_hints(r, q, la.lambda, la.mu);
        }
    }
    return fp12_conjugate(f);
}

inline bool fp12_is_one(const Fp12& f) { return fp12_eq(f, FP12_ONE); }

// e(P,Q). Either point at infinity → 1.
inline Fp12 pairing(const G1& p, const G2& q) {
    if (g1_is_identity(p) || g2_is_identity(q)) return FP12_ONE;
    return final_exp(miller_loop(p, q));
}

} // namespace zeg::bls

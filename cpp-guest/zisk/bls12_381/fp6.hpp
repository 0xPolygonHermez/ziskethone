// fp6.hpp — BLS12-381 sextic extension Fp6 = Fp2[v]/(v³ - (1+u)).
//
// Layer 3a of the KZG port. Fp6 = c0 + c1·v + c2·v² (three Fp2, 36 u64).
// All ops are built on the Fp2 layer (which carries the ZEG_ZISK backend), so
// this file is backend-agnostic. Faithful to zisklib/lib/bls12_381/fp6.rs
// (×(1+u) via fp2_mul_by_nonresidue; v multiply via the "sparse_mula" helper).

#pragma once

#include "fp2.hpp"

namespace zeg::bls {

struct Fp6 { Fp2 c0, c1, c2; };  // c0 + c1·v + c2·v²

inline constexpr Fp6 FP6_ZERO = {FP2_ZERO, FP2_ZERO, FP2_ZERO};
inline constexpr Fp6 FP6_ONE  = {FP2_ONE,  FP2_ZERO, FP2_ZERO};

inline bool fp6_eq(const Fp6& a, const Fp6& b) { return fp2_eq(a.c0,b.c0) && fp2_eq(a.c1,b.c1) && fp2_eq(a.c2,b.c2); }
inline bool fp6_is_zero(const Fp6& a) { return fp2_is_zero(a.c0) && fp2_is_zero(a.c1) && fp2_is_zero(a.c2); }

inline Fp6 fp6_add(const Fp6& a, const Fp6& b) { return { fp2_add(a.c0,b.c0), fp2_add(a.c1,b.c1), fp2_add(a.c2,b.c2) }; }
inline Fp6 fp6_sub(const Fp6& a, const Fp6& b) { return { fp2_sub(a.c0,b.c0), fp2_sub(a.c1,b.c1), fp2_sub(a.c2,b.c2) }; }
inline Fp6 fp6_dbl(const Fp6& a) { return { fp2_dbl(a.c0), fp2_dbl(a.c1), fp2_dbl(a.c2) }; }
inline Fp6 fp6_neg(const Fp6& a) { return { fp2_neg(a.c0), fp2_neg(a.c1), fp2_neg(a.c2) }; }

// nr(x) = x·(1+u), the Fp6 modulus residue.
inline Fp2 nr(const Fp2& x) { return fp2_mul_by_nonresidue(x); }

inline Fp6 fp6_mul(const Fp6& a, const Fp6& b) {
    Fp2 c0 = fp2_add(fp2_mul(a.c0,b.c0), nr(fp2_add(fp2_mul(a.c1,b.c2), fp2_mul(a.c2,b.c1))));
    Fp2 c1 = fp2_add(fp2_add(fp2_mul(a.c0,b.c1), fp2_mul(a.c1,b.c0)), nr(fp2_mul(a.c2,b.c2)));
    Fp2 c2 = fp2_add(fp2_add(fp2_mul(a.c0,b.c2), fp2_mul(a.c1,b.c1)), fp2_mul(a.c2,b.c0));
    return { c0, c1, c2 };
}

inline Fp6 fp6_sqr(const Fp6& a) {
    Fp2 c0 = fp2_add(fp2_sqr(a.c0), nr(fp2_dbl(fp2_mul(a.c1,a.c2))));
    Fp2 c1 = fp2_add(nr(fp2_sqr(a.c2)), fp2_dbl(fp2_mul(a.c0,a.c1)));
    Fp2 c2 = fp2_add(fp2_sqr(a.c1), fp2_dbl(fp2_mul(a.c0,a.c2)));
    return { c0, c1, c2 };
}

inline Fp6 fp6_inv(const Fp6& a) {
    Fp2 t0 = fp2_sub(fp2_sqr(a.c0), nr(fp2_mul(a.c1,a.c2)));      // c1mid
    Fp2 t1 = fp2_sub(nr(fp2_sqr(a.c2)), fp2_mul(a.c0,a.c1));      // c2mid
    Fp2 t2 = fp2_sub(fp2_sqr(a.c1), fp2_mul(a.c0,a.c2));          // c3mid
    Fp2 f  = fp2_add(fp2_mul(a.c0,t0), nr(fp2_add(fp2_mul(a.c2,t1), fp2_mul(a.c1,t2))));
    Fp2 fi = fp2_inv(f);
    return { fp2_mul(t0,fi), fp2_mul(t1,fi), fp2_mul(t2,fi) };
}

// a · (b2·v)
inline Fp6 fp6_sparse_mula(const Fp6& a, const Fp2& b2) {
    return { nr(fp2_mul(a.c2,b2)), fp2_mul(a.c0,b2), fp2_mul(a.c1,b2) };
}
// a · (b2·v + b3·v²)
inline Fp6 fp6_sparse_mulb(const Fp6& a, const Fp2& b2, const Fp2& b3) {
    Fp2 c0 = nr(fp2_add(fp2_mul(a.c1,b3), fp2_mul(a.c2,b2)));
    Fp2 c1 = fp2_add(fp2_mul(a.c0,b2), nr(fp2_mul(a.c2,b3)));
    Fp2 c2 = fp2_add(fp2_mul(a.c0,b3), fp2_mul(a.c1,b2));
    return { c0, c1, c2 };
}
// a · (b1 + b3·v²)
inline Fp6 fp6_sparse_mulc(const Fp6& a, const Fp2& b1, const Fp2& b3) {
    Fp2 c0 = fp2_add(fp2_mul(a.c0,b1), nr(fp2_mul(a.c1,b3)));
    Fp2 c1 = fp2_add(fp2_mul(a.c1,b1), nr(fp2_mul(a.c2,b3)));
    Fp2 c2 = fp2_add(fp2_mul(a.c0,b3), fp2_mul(a.c2,b1));
    return { c0, c1, c2 };
}
// a · v
inline Fp6 fp6_mul_by_v(const Fp6& a) { return fp6_sparse_mula(a, FP2_ONE); }

} // namespace zeg::bls

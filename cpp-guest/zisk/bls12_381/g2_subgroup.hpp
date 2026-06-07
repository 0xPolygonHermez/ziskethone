// g2_subgroup.hpp — BLS12-381 G2 subgroup membership (EIP-2537 mul/msm/pairing).
//
// Untwist-Frobenius-twist endomorphism ψ and the subgroup test
//   P ∈ G2  ⟺  [x]·ψ³(P) + P == ψ²(P)
// (x = curve parameter, negative). Reuses EXT_U_INV (pairing.hpp), the Frobenius
// γ13/γ14 (fp12.hpp), and the guarded G2 ops (g2.hpp). Faithful to
// zisklib twist.rs (utf_endomorphism_twist / is_on_subgroup_twist).

#pragma once

#include "pairing.hpp"   // brings g2.hpp, fp12.hpp (GAMMA13/14), EXT_U_INV

namespace zeg::bls {

// ψ(P): φ⁻¹ ∘ π_p ∘ φ. Each coordinate: ·EXT_U_INV, conj, ·γ (γ14 scalar/Fp on x,
// γ13/Fp2 on y), then ·(1+u).
inline G2 g2_utf(const G2& p) {
    Fp2 x = fp2_mul(p.x, EXT_U_INV);
    Fp2 y = fp2_mul(p.y, EXT_U_INV);
    x = fp2_scalar_mul(fp2_conjugate(x), GAMMA14);   // γ14 ∈ Fp
    y = fp2_mul(fp2_conjugate(y), GAMMA13);           // γ13 ∈ Fp2
    x = fp2_mul_by_nonresidue(x);                     // ·(1+u)
    y = fp2_mul_by_nonresidue(y);
    return { x, y };
}

inline bool g2_is_on_subgroup(const G2& p) {
    if (g2_is_identity(p)) return true;
    G2 u1 = g2_utf(p);          // ψ(P)
    G2 u2 = g2_utf(u1);         // ψ²(P)
    G2 u3 = g2_utf(u2);         // ψ³(P)
    uint64_t absx[4] = {0xD201000000010000ULL, 0, 0, 0};  // |x|
    G2 xu3 = g2_scalar_mul(u3, absx);                     // [|x|]ψ³(P)
    G2 lhs = g2_add_complete(g2_neg(xu3), p);            // [x]ψ³(P) + P
    return g2_eq(lhs, u2);
}

} // namespace zeg::bls

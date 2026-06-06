// kzg.hpp — EIP-4844 KZG point-evaluation verification core (BLS12-381).
//
// Layer 7 of the KZG port. kzg_verify_core implements the pairing check
//   e(C - [y]G₁, G₂) == e(π, [τ]₂ - [z]G₂)
// (no versioned-hash check — that wrapper, which needs sha256, lives in the
// integration TU). Faithful to zisklib/lib/bls12_381/kzg.rs, built on the
// verified G1/G2/pairing layers. Backend-agnostic.

#pragma once

#include "pairing.hpp"

namespace zeg::bls {

// Scalar field order r (= EIP-4844 BLS_MODULUS), little-endian.
inline constexpr uint64_t BLS_R[4] = {0xFFFFFFFF00000001ULL,0x53BDA402FFFE5BFEULL,
                                      0x3339D80809A1D805ULL,0x73EDA753299D7D48ULL};
// Trusted setup [τ]₂ (zisklib TRUSTED_SETUP_TAU_G2): x.c0,x.c1,y.c0,y.c1.
inline constexpr G2 KZG_SETUP_G2_TAU = {
    {{{0xc98edada20c1def2ULL,0x087041de621000edULL,0xa36851477ba4c60bULL,0x3926c911cceceac9ULL,0x734429b7b38608e2ULL,0x185cbfee53492714ULL}},
     {{0xafaaab24f3499f72ULL,0x2914e5870cb452d2ULL,0x1009a2ce615ac53dULL,0x26187075cbfbefa8ULL,0x843bc287230af389ULL,0x15bfd7dd8cdeb128ULL}}},
    {{{0xee689bfbbb832a99ULL,0x4ce26d105941f383ULL,0xe82451a496a9c979ULL,0x131569490e28de18ULL,0xd7d5ee8599d1fca2ULL,0x014353bdb96b626dULL}},
     {{0x23048ef30d0a154fULL,0x9495346f3d7ac9cdULL,0xda5ed1ba9bfa0789ULL,0xef79de09fc63671fULL,0x03432fcae0181b4bULL,0x1666c54b0a325295ULL}}}};

// 32-byte big-endian scalar → [u64;4] LE, returns false if not canonical (>= r).
inline bool kzg_scalar_canonical(const uint8_t b[32], uint64_t out[4]) {
    for (int i = 0; i < 4; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) v |= (uint64_t)b[i*8 + j] << (8 * (7 - j));
        out[3 - i] = v;
    }
    for (int i = 3; i >= 0; --i) { if (out[i] < BLS_R[i]) return true; if (out[i] > BLS_R[i]) return false; }
    return false;  // == r
}

// Core KZG verify. z,y: 32-byte BE scalars; commitment,proof: 48-byte compressed G1.
inline bool kzg_verify_core(const uint8_t z[32], const uint8_t y[32],
                            const uint8_t commitment[48], const uint8_t proof[48]) {
    G1 C, Pi; bool c_inf, p_inf;
    if (!g1_decompress(commitment, &C, &c_inf)) return false;
    if (!c_inf && !g1_is_on_subgroup(C)) return false;
    if (!g1_decompress(proof, &Pi, &p_inf)) return false;
    if (!p_inf && !g1_is_on_subgroup(Pi)) return false;

    uint64_t zz[4], yy[4];
    if (!kzg_scalar_canonical(z, zz)) return false;
    if (!kzg_scalar_canonical(y, yy)) return false;

    // C - [y]G₁
    G1 yG1 = g1_scalar_mul(G1_GENERATOR, yy);
    G1 c_minus_y = g1_sub_complete(C, yG1);
    // [τ]₂ - [z]G₂
    G2 zG2 = g2_scalar_mul(G2_GENERATOR, zz);
    G2 t_minus_z = g2_sub_complete(KZG_SETUP_G2_TAU, zG2);

    bool cy_inf = g1_is_identity(c_minus_y);
    bool pi_inf = g1_is_identity(Pi);
    bool tz_inf = g2_is_identity(t_minus_z);

    // e(O,G₂)=1 ⇒ need RHS=1 ⇒ π=O or [τ-z]₂=O.
    if (cy_inf) return pi_inf || tz_inf;
    // LHS≠1 but RHS=1 ⇒ fail.
    if (pi_inf || tz_inf) return false;

    // e(c_minus_y, -G₂) · e(π, t_minus_z) == 1
    G2 neg_g2 = g2_neg(G2_GENERATOR);
    Fp12 ml = fp12_mul(miller_loop(c_minus_y, neg_g2), miller_loop(Pi, t_minus_z));
    return fp12_is_one(final_exp(ml));
}

} // namespace zeg::bls

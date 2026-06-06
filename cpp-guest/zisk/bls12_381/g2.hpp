// g2.hpp — BLS12-381 G2 twist E': y² = x³ + 4(1+u) over Fp2.
//
// Layer 5 of the KZG port. Affine G2 = (x, y) with x,y ∈ Fp2 (24 u64). There is
// no G2 curve precompile, so all ops are affine formulas over Fp2 (which carry
// the ZEG_ZISK backend through the complex precompiles + fp2_inv fcall). scalar-
// mul reuses the msb_pos_256 fcall from g1.hpp. KZG only needs add/neg/sub/
// scalar-mul over hardcoded constants — no G2 decompression or subgroup check.
// Faithful to zisklib/lib/bls12_381/twist.rs.

#pragma once

#include "fp2.hpp"
#include "g1.hpp"   // for msb_pos_256

namespace zeg::bls {

struct G2 { Fp2 x, y; };  // affine; (0,0) == identity

inline constexpr G2 G2_IDENTITY = {FP2_ZERO, FP2_ZERO};
inline constexpr Fp2 E2_B = {{{4,0,0,0,0,0}}, {{4,0,0,0,0,0}}};  // 4·(1+u)
inline constexpr G2 G2_GENERATOR = {
    {{{0xD48056C8C121BDB8ULL,0x0BAC0326A805BBEFULL,0xB4510B647AE3D177ULL,0xC6E47AD4FA403B02ULL,0x260805272DC51051ULL,0x024AA2B2F08F0A91ULL}},
     {{0xE5AC7D055D042B7EULL,0x334CF11213945D57ULL,0xB5DA61BBDC7F5049ULL,0x596BD0D09920B61AULL,0x7DACD3A088274F65ULL,0x13E02B6052719F60ULL}}},
    {{{0xE193548608B82801ULL,0x923AC9CC3BACA289ULL,0x6D429A695160D12CULL,0xADFD9BAA8CBDD3A7ULL,0x8CC9CDC6DA2E351AULL,0x0CE5D527727D6E11ULL}},
     {{0xAAA9075FF05F79BEULL,0x3F370D275CEC1DA1ULL,0x267492AB572E99ABULL,0xCB3E287E85A763AFULL,0x32ACD2B02BC28B99ULL,0x0606C4A02EA734CCULL}}}};

inline bool g2_eq(const G2& a, const G2& b) { return fp2_eq(a.x,b.x) && fp2_eq(a.y,b.y); }
inline bool g2_is_identity(const G2& p) { return fp2_is_zero(p.x) && fp2_is_zero(p.y); }
inline G2 g2_neg(const G2& p) { return { p.x, fp2_neg(p.y) }; }

inline bool g2_is_on_curve(const G2& p) {               // y² == x³ + 4(1+u)
    Fp2 lhs = fp2_sqr(p.y);
    Fp2 rhs = fp2_add(fp2_mul(fp2_sqr(p.x), p.x), E2_B);
    return fp2_eq(lhs, rhs);
}

inline G2 g2_dbl(const G2& p) {                          // requires y != 0
    Fp three{{3,0,0,0,0,0}};
    Fp2 lam = fp2_inv(fp2_dbl(p.y));
    lam = fp2_scalar_mul(lam, three);
    lam = fp2_mul(lam, p.x);
    lam = fp2_mul(lam, p.x);                             // 3x²/(2y)
    Fp2 x3 = fp2_sub(fp2_sub(fp2_sqr(lam), p.x), p.x);
    Fp2 y3 = fp2_sub(fp2_mul(lam, fp2_sub(p.x, x3)), p.y);
    return { x3, y3 };
}
// add of two non-identity points (handles x1==x2 → double / infinity).
inline G2 g2_add(const G2& a, const G2& b) {
    if (fp2_eq(a.x, b.x)) return fp2_eq(a.y, b.y) ? g2_dbl(a) : G2_IDENTITY;
    Fp2 lam = fp2_mul(fp2_sub(b.y, a.y), fp2_inv(fp2_sub(b.x, a.x)));
    Fp2 x3 = fp2_sub(fp2_sub(fp2_sqr(lam), a.x), b.x);
    Fp2 y3 = fp2_sub(fp2_mul(lam, fp2_sub(a.x, x3)), a.y);
    return { x3, y3 };
}
inline G2 g2_sub(const G2& a, const G2& b) { return g2_add(a, g2_neg(b)); }
inline G2 g2_add_complete(const G2& a, const G2& b) {
    if (g2_is_identity(a)) return b;
    if (g2_is_identity(b)) return a;
    return g2_add(a, b);
}

// k·P for non-identity P, k ∈ Fr (4 limbs). MSB hinted, scalar recomposed.
inline G2 g2_scalar_mul(const G2& p, const uint64_t k[4]) {
    if (k[0]==0 && k[1]==0 && k[2]==0 && k[3]==0) return G2_IDENTITY;
    if (k[0]==1 && k[1]==0 && k[2]==0 && k[3]==0) return p;
    if (k[0]==2 && k[1]==0 && k[2]==0 && k[3]==0) return g2_dbl(p);
    uint64_t ml, mb; msb_pos_256(k, &ml, &mb);
    if (((k[ml] >> mb) & 1) != 1) { for (;;) {} }
    G2 q = p;
    uint64_t krec[4] = {0,0,0,0}; krec[ml] = 1ULL << mb;
    int li = (int)ml, curbit;
    if (mb == 0) { li -= 1; curbit = 63; } else curbit = (int)mb - 1;
    for (int i = li; i >= 0; --i) {
        for (int j = curbit; j >= 0; --j) {
            q = g2_dbl(q);
            if ((k[i] >> j) & 1ULL) { q = g2_add(q, p); krec[i] |= 1ULL << j; }
        }
        curbit = 63;
    }
    if (krec[0]!=k[0]||krec[1]!=k[1]||krec[2]!=k[2]||krec[3]!=k[3]) { for (;;) {} }
    return q;
}

} // namespace zeg::bls

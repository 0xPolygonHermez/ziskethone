// g1.hpp — BLS12-381 G1 curve E: y² = x³ + 4 over Fp.
//
// Layer 4 of the KZG port. Affine points G1 = (x, y) (12 u64); the all-zero
// point is the identity sentinel (G1_IDENTITY). Dual backend (ZEG_ZISK):
// add/double via the curve precompiles (CSR 0x80C/0x80D); msb_pos_256 fcall
// (id 17) for scalar-mul bit length, verified by recomposition. Software path
// uses affine formulas for host tests. Faithful to zisklib/lib/bls12_381/curve.rs.
//
// Provides what KZG needs: decompress (48-B compressed), on-curve + subgroup
// checks, add (complete), neg, sub, scalar-mul.

#pragma once

#include "fp.hpp"

namespace zeg::bls {

struct G1 { Fp x, y; };  // affine; (0,0) == point at infinity

inline constexpr G1 G1_IDENTITY = {FP_ZERO, FP_ZERO};
inline constexpr Fp E_B = {{4, 0, 0, 0, 0, 0}};                       // curve b
inline constexpr Fp GAMMA = {{0x8BFD00000000AAACULL,0x409427EB4F49FFFDULL,0x897D29650FB85F9BULL,
                              0xAA0D857D89759AD4ULL,0xEC02408663D4DE85ULL,0x1A0111EA397FE699ULL}};
// G1 generator (zisklib constants.rs)
inline constexpr G1 G1_GENERATOR = {
    {{0xFB3AF00ADB22C6BBULL,0x6C55E83FF97A1AEFULL,0xA14E3A3F171BAC58ULL,0xC3688C4F9774B905ULL,0x2695638C4FA9AC0FULL,0x17F1D3A73197D794ULL}},
    {{0x0CAA232946C5E7E1ULL,0xD03CC744A2888AE4ULL,0x00DB18CB2C04B3EDULL,0xFCF5E095D5D00AF6ULL,0xA09E30ED741D8AE4ULL,0x08B3F481E3AAA0F1ULL}}};

inline bool g1_eq(const G1& a, const G1& b) { return fp_eq(a.x,b.x) && fp_eq(a.y,b.y); }
inline bool g1_is_identity(const G1& p) { return fp_is_zero(p.x) && fp_is_zero(p.y); }
inline G1 g1_neg(const G1& p) { return { p.x, fp_neg(p.y) }; }

// ---- backend: raw add/double primitives -----------------------------------
#if defined(ZEG_ZISK)
inline G1 g1_add_raw(const G1& a, const G1& b) {        // requires x_a != x_b
    G1 p1 = a, p2 = b;
    struct { uint64_t* p1; const uint64_t* p2; } pp{ reinterpret_cast<uint64_t*>(&p1),
                                                     reinterpret_cast<const uint64_t*>(&p2) };
    asm volatile("csrs 0x80C, %0" : : "r"(&pp) : "memory");
    return p1;
}
inline G1 g1_dbl_raw(const G1& a) {                     // requires y != 0
    G1 p = a;
    asm volatile("csrs 0x80D, %0" : : "r"(reinterpret_cast<uint64_t*>(&p)) : "memory");
    return p;
}
inline void msb_pos_256(const uint64_t k[4], uint64_t* limb, uint64_t* bit) {
    uint64_t one = 1;
    asm volatile("csrs 0x8F0, %0" : : "r"(one) : "memory");
    asm volatile("csrs 0x8F2, %0" : : "r"(k)   : "memory");
    asm volatile("csrwi 0x8C0, 17" : : : "memory");      // FCALL_MSB_POS_256_ID
    uint64_t l, b; asm volatile("csrr %0, 0xFFE" : "=r"(l)); asm volatile("csrr %0, 0xFFE" : "=r"(b));
    *limb = l; *bit = b;
}
#else
// complete affine add (handles equal/inverse/identity) — for host tests.
inline G1 g1_add_raw(const G1& a, const G1& b) {
    if (g1_is_identity(a)) return b;
    if (g1_is_identity(b)) return a;
    if (fp_eq(a.x, b.x)) {
        if (!fp_eq(a.y, b.y)) return G1_IDENTITY;        // a + (-a)
        Fp three{{3,0,0,0,0,0}};
        Fp lam = fp_mul(fp_mul(fp_sqr(a.x), three), fp_inv(fp_dbl(a.y)));
        Fp x3 = fp_sub(fp_sqr(lam), fp_dbl(a.x));
        Fp y3 = fp_sub(fp_mul(lam, fp_sub(a.x, x3)), a.y);
        return { x3, y3 };
    }
    Fp lam = fp_mul(fp_sub(b.y, a.y), fp_inv(fp_sub(b.x, a.x)));
    Fp x3 = fp_sub(fp_sub(fp_sqr(lam), a.x), b.x);
    Fp y3 = fp_sub(fp_mul(lam, fp_sub(a.x, x3)), a.y);
    return { x3, y3 };
}
inline G1 g1_dbl_raw(const G1& a) { return g1_add_raw(a, a); }
inline void msb_pos_256(const uint64_t k[4], uint64_t* limb, uint64_t* bit) {
    for (int i = 3; i >= 0; --i) if (k[i]) {
        uint64_t w = k[i], pos = 0;
        if (w >= (1ULL<<32)){w>>=32;pos+=32;} if (w >= (1ULL<<16)){w>>=16;pos+=16;}
        if (w >= (1ULL<<8)){w>>=8;pos+=8;} if (w >= (1ULL<<4)){w>>=4;pos+=4;}
        if (w >= (1ULL<<2)){w>>=2;pos+=2;} if (w >= (1ULL<<1)){pos+=1;}
        *limb = (uint64_t)i; *bit = pos; return;
    }
    *limb = 0; *bit = 0;
}
#endif

// ---- shared higher-level ops ----------------------------------------------
inline bool g1_is_on_curve(const G1& p) {               // y² == x³ + 4
    Fp lhs = fp_sqr(p.y);
    Fp rhs = fp_add(fp_mul(fp_sqr(p.x), p.x), E_B);
    return fp_eq(lhs, rhs);
}

// add of two non-identity points (handles x equal → double / infinity).
inline G1 g1_add(const G1& a, const G1& b) {
    if (fp_eq(a.x, b.x)) return fp_eq(a.y, b.y) ? g1_dbl_raw(a) : G1_IDENTITY;
    return g1_add_raw(a, b);
}
inline G1 g1_sub(const G1& a, const G1& b) { return g1_add(a, g1_neg(b)); }

// complete add (either may be infinity) — used by the KZG glue.
inline G1 g1_add_complete(const G1& a, const G1& b) {
    if (g1_is_identity(a)) return b;
    if (g1_is_identity(b)) return a;
    return g1_add(a, b);
}

// k·P for non-identity P, k ∈ Fr (4 limbs). MSB hinted, scalar recomposed.
inline G1 g1_scalar_mul(const G1& p, const uint64_t k[4]) {
    if (k[0]==0 && k[1]==0 && k[2]==0 && k[3]==0) return G1_IDENTITY;
    if (k[0]==1 && k[1]==0 && k[2]==0 && k[3]==0) return p;
    if (k[0]==2 && k[1]==0 && k[2]==0 && k[3]==0) return g1_dbl_raw(p);
    uint64_t ml, mb; msb_pos_256(k, &ml, &mb);
    if (((k[ml] >> mb) & 1) != 1) { for (;;) {} }
    G1 q = p;
    uint64_t krec[4] = {0,0,0,0}; krec[ml] = 1ULL << mb;
    int li = (int)ml, curbit;
    if (mb == 0) { li -= 1; curbit = 63; } else curbit = (int)mb - 1;
    for (int i = li; i >= 0; --i) {
        for (int j = curbit; j >= 0; --j) {
            q = g1_dbl_raw(q);
            if ((k[i] >> j) & 1ULL) { q = g1_add_raw(q, p); krec[i] |= 1ULL << j; }
        }
        curbit = 63;
    }
    if (krec[0]!=k[0]||krec[1]!=k[1]||krec[2]!=k[2]||krec[3]!=k[3]) { for (;;) {} }
    return q;
}

// scalar-mul by a fixed big-endian bit string (first bit = MSB = 1), MSB-first.
inline G1 g1_scalar_mul_bin(const G1& p, const uint8_t* bits, int n) {
    G1 r = p;
    for (int i = 1; i < n; ++i) { r = g1_dbl_raw(r); if (bits[i]) r = g1_add_raw(r, p); }
    return r;
}
inline G1 g1_sigma(const G1& p) { return { fp_mul(p.x, GAMMA), p.y }; }  // σ(x,y)=(γx,y)

// subgroup check: ((x²-1)/3)·(2σ(P) - P - σ²(P)) == σ²(P)
inline bool g1_is_on_subgroup(const G1& p) {
    static const uint8_t X2DIV3_BIN_BE[126] = {
        1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,0,0,0,1,1,0,0,0,0,0,0,0,0,0,0,
        0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,1,1,1,0,0,0,0,1,0,1,0,1,0,1,
        1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,
        0,1,0,1,0,1};
    G1 s1 = g1_sigma(p);
    G1 rhs = g1_sigma(s1);                               // σ²(P)
    G1 lhs = g1_sub(g1_sub(g1_dbl_raw(s1), p), rhs);     // 2σ(P) - P - σ²(P)
    lhs = g1_scalar_mul_bin(lhs, X2DIV3_BIN_BE, 126);
    return g1_eq(lhs, rhs);
}

// 48-byte compressed → (point, is_infinity). Returns false on invalid input.
inline bool g1_decompress(const uint8_t in[48], G1* out, bool* is_inf) {
    uint8_t flags = in[0];
    if ((flags & 0x80) == 0) return false;               // must be compressed
    if (flags & 0x40) {                                  // infinity
        if (flags & 0x3f) return false;
        for (int i = 1; i < 48; ++i) if (in[i]) return false;
        *out = G1_IDENTITY; *is_inf = true; return true;
    }
    bool y_sign = (flags & 0x20) != 0;
    uint8_t bytes[48]; for (int i = 0; i < 48; ++i) bytes[i] = in[i];
    bytes[0] &= 0x1f;
    Fp x = fp_from_bytes_be(bytes);
    if (!fp_lt(x, FP_P)) return false;
    Fp y_sq = fp_add(fp_mul(fp_sqr(x), x), E_B);         // x³ + 4
    bool has; Fp y = fp_sqrt(y_sq, &has);
    if (!has) return false;
    Fp y_neg = fp_neg(y);
    bool y_is_larger = fp_lt(y_neg, y);
    Fp final_y = (y_is_larger == y_sign) ? y : y_neg;
    *out = { x, final_y }; *is_inf = false; return true;
}

} // namespace zeg::bls

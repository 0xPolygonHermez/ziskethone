// g1.hpp — BN254 G1 group E: y² = x³ + 3 over Fp.
//
// Layer 4 of the BN254 port. Affine points G1 = (x, y) (8 u64). Dual backend
// (ZEG_ZISK): add/double via the bn254 curve precompiles (CSR 0x806/0x807);
// msb_pos_256 fcall (id 17) for scalar-mul bit length, verified by recomposition.
// Software path uses affine formulas for host tests. BN254 G1 has cofactor 1, so
// every on-curve, in-field point is in the prime-order subgroup (no subgroup
// check needed). Faithful to zisklib/lib/bn254/curve.rs.

#pragma once

#include "fp.hpp"
#include "constants.hpp"

namespace zeg::bn {

struct G1 { Fp x, y; };  // affine; (0,0) = point at infinity

inline constexpr G1 G1_IDENTITY = {FP_ZERO, FP_ZERO};

inline bool g1_eq(const G1& a, const G1& b) { return fp_eq(a.x,b.x) && fp_eq(a.y,b.y); }
inline bool g1_is_identity(const G1& p) { return fp_is_zero(p.x) && fp_is_zero(p.y); }
inline G1 g1_neg(const G1& p) { return { p.x, fp_neg(p.y) }; }

// on curve: y² == x³ + 3  (for non-identity points)
inline bool g1_is_on_curve(const G1& p) {
    Fp lhs = fp_sqr(p.y);
    Fp rhs = fp_add(fp_mul(fp_sqr(p.x), p.x), E_B);
    return fp_eq(lhs, rhs);
}
// field-canonical: both coords < p
inline bool g1_in_field(const G1& p) { return fp_lt(p.x, FP_P) && fp_lt(p.y, FP_P); }

// ===========================================================================
// Backend: raw add (x1 != x2) / double, and the msb_pos_256 fcall.
// ===========================================================================
#if defined(ZEG_ZISK)

inline G1 g1_add_raw(const G1& a, const G1& b) {  // requires x_a != x_b
    G1 p1 = a, p2 = b;
    struct { uint64_t* p1; const uint64_t* p2; } pp{
        reinterpret_cast<uint64_t*>(&p1), reinterpret_cast<const uint64_t*>(&p2) };
    asm volatile("csrs 0x806, %0" : : "r"(&pp) : "memory");
    return p1;
}
inline G1 g1_dbl_raw(const G1& a) {  // requires y != 0
    G1 p = a;
    asm volatile("csrs 0x807, %0" : : "r"(reinterpret_cast<uint64_t*>(&p)) : "memory");
    return p;
}
inline void msb_pos_256(const uint64_t k[4], uint64_t* limb, uint64_t* bit) {
    uint64_t one = 1;
    asm volatile("csrs 0x8F0, %0" : : "r"(one) : "memory");
    asm volatile("csrs 0x8F2, %0" : : "r"(k)   : "memory");
    asm volatile("csrwi 0x8C0, 17" : : : "memory");
    uint64_t l, b; l = ({ uint64_t v; asm volatile("csrr %0, 0xFFE" : "=r"(v)); v; });
    b = ({ uint64_t v; asm volatile("csrr %0, 0xFFE" : "=r"(v)); v; });
    *limb = l; *bit = b;
}

#else  // ===================== portable software (host) =====================

inline G1 g1_add_raw(const G1& a, const G1& b) {  // a + b, x_a != x_b
    Fp dx = fp_sub(b.x, a.x), dy = fp_sub(b.y, a.y);
    Fp lam = fp_mul(dy, fp_inv(dx));
    Fp x3 = fp_sub(fp_sub(fp_sqr(lam), a.x), b.x);
    Fp y3 = fp_sub(fp_mul(lam, fp_sub(a.x, x3)), a.y);
    return { x3, y3 };
}
inline G1 g1_dbl_raw(const G1& a) {  // 2a, y != 0
    Fp xx = fp_sqr(a.x);
    Fp lam = fp_mul(fp_add(fp_add(xx, xx), xx), fp_inv(fp_add(a.y, a.y)));  // 3x²/2y
    Fp x3 = fp_sub(fp_sqr(lam), fp_add(a.x, a.x));
    Fp y3 = fp_sub(fp_mul(lam, fp_sub(a.x, x3)), a.y);
    return { x3, y3 };
}
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

#endif  // backend

// ===========================================================================
// Shared G1 ops.
// ===========================================================================
// complete affine add (handles ∞, doubling, opposite) — routes equal-x away from
// the raw add precompile, which is undefined on equal x.
inline G1 g1_add_complete(const G1& a, const G1& b) {
    if (g1_is_identity(a)) return b;
    if (g1_is_identity(b)) return a;
    if (fp_eq(a.x, b.x)) {
        if (fp_eq(a.y, b.y)) return g1_dbl_raw(a);
        return G1_IDENTITY;  // a + (-a)
    }
    return g1_add_raw(a, b);
}

// k·P for non-identity P. k must already be reduced mod r (k < r). Returns the
// MSB-position-hinted double-and-add, verified by recomposing k.
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

// reduce a 256-bit scalar mod r by repeated subtraction (k/r < 5). No precompile.
inline void fr_reduce(const uint64_t k[4], uint64_t out[4]) {
    uint64_t t[4] = {k[0], k[1], k[2], k[3]};
    auto ge_r = [&]() {
        for (int i = 3; i >= 0; --i) { if (t[i] > FR_R.c[i]) return true; if (t[i] < FR_R.c[i]) return false; }
        return true;  // equal
    };
    while (ge_r()) {
        unsigned __int128 borrow = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 d = (unsigned __int128)t[i] - FR_R.c[i] - borrow;
            t[i] = (uint64_t)d; borrow = (d >> 64) & 1;
        }
    }
    for (int i = 0; i < 4; ++i) out[i] = t[i];
}

} // namespace zeg::bn

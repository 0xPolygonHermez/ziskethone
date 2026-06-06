// fp.hpp — BN254 base field Fp (256-bit) for the alt_bn128 precompile port.
//
// Layer 1 of the self-contained C++ port of ziskos's zisklib BN254. Dual backend,
// selected by ZEG_ZISK (mirrors secp256k1.cpp / bls12_381/fp.hpp):
//   ZEG_ZISK : field mul/add via the ZisK arith256_mod precompile (CSR 0x802);
//              inverse via the bn254 fp_inv fcall hint (id 6), verified in-circuit.
//   else     : portable software (512-bit mul + reduce, Fermat inverse) for host
//              unit tests against evmone's bn254 reference.
//
// EIP-196/197 needs no field sqrt, so none is provided. Faithful to
// zisklib/lib/bn254/fp.rs. Limbs are little-endian uint64_t[4].

#pragma once

#include <cstdint>
#include <cstring>

namespace zeg::bn {

struct Fp { uint64_t c[4]; };

// ---- constants (little-endian limbs), from zisklib bn254/constants.rs ------
inline constexpr Fp FP_P = {{0x3C208C16D87CFD47ULL, 0x97816A916871CA8DULL,
                             0xB85045B68181585DULL, 0x30644E72E131A029ULL}};
inline constexpr Fp FP_P_MINUS_ONE = {{0x3C208C16D87CFD46ULL, 0x97816A916871CA8DULL,
                                       0xB85045B68181585DULL, 0x30644E72E131A029ULL}};
inline constexpr Fp FP_ZERO = {{0, 0, 0, 0}};
inline constexpr Fp FP_ONE = {{1, 0, 0, 0}};

inline bool fp_eq(const Fp& a, const Fp& b) {
    return std::memcmp(a.c, b.c, sizeof(a.c)) == 0;
}
inline bool fp_is_zero(const Fp& a) { return fp_eq(a, FP_ZERO); }
inline bool fp_lt(const Fp& a, const Fp& b) {  // a < b as 256-bit integers
    for (int i = 3; i >= 0; --i) { if (a.c[i] < b.c[i]) return true; if (a.c[i] > b.c[i]) return false; }
    return false;
}

// ===========================================================================
// Backend: arith256_mod (d = a*b + c mod p) and the fp_inv fcall hint.
// ===========================================================================
#if defined(ZEG_ZISK)

// ZisK arith256_mod precompile (CSR 0x802). Params = SyscallArith256ModParams.
inline void fp_muladd_mod(const Fp& a, const Fp& b, const Fp& c, const Fp& m, Fp& d) {
    struct { const uint64_t* a; const uint64_t* b; const uint64_t* c;
             const uint64_t* module; uint64_t* d; } p{a.c, b.c, c.c, m.c, d.c};
    asm volatile("csrs 0x802, %0" : : "r"(&p) : "memory");
}

inline uint64_t fcall_get() {
    uint64_t v; asm volatile("csrr %0, 0xFFE" : "=r"(v)); return v;
}
// 1/x mod p (hint only; verified by the caller). Param x = 4 words → CSR 0x8F2.
inline Fp fcall_fp_inv(const Fp& x) {
    asm volatile("csrs 0x8F2, %0" : : "r"(x.c) : "memory");
    asm volatile("csrwi 0x8C0, 6" : : : "memory");  // FCALL_BN254_FP_INV_ID
    Fp r; for (int i = 0; i < 4; ++i) r.c[i] = fcall_get();
    return r;
}

#else  // ===================== portable software (host) =====================

namespace detail {
inline void mul4(const uint64_t a[4], const uint64_t b[4], uint64_t out[8]) {
    for (int i = 0; i < 8; ++i) out[i] = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned __int128 t = (unsigned __int128)a[i] * b[j] + out[i + j] + carry;
            out[i + j] = (uint64_t)t; carry = (uint64_t)(t >> 64);
        }
        out[i + 4] += carry;
    }
}
inline bool ge_512_256(const uint64_t r[8], const uint64_t m[4]) {
    for (int i = 7; i >= 4; --i) if (r[i]) return true;
    for (int i = 3; i >= 0; --i) { if (r[i] > m[i]) return true; if (r[i] < m[i]) return false; }
    return true;  // equal
}
inline void sub_m_512(uint64_t r[8], const uint64_t m[4]) {
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t mi = (i < 4) ? m[i] : 0;
        unsigned __int128 t = (unsigned __int128)r[i] - mi - borrow;
        r[i] = (uint64_t)t; borrow = (t >> 64) & 1;
    }
}
inline void mod512(const uint64_t num[8], const uint64_t m[4], uint64_t out[4]) {
    uint64_t r[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 511; i >= 0; --i) {
        uint64_t carry = 0;
        for (int k = 0; k < 8; ++k) { uint64_t nx = (r[k] >> 63) & 1; r[k] = (r[k] << 1) | carry; carry = nx; }
        r[0] |= (num[i >> 6] >> (i & 63)) & 1ULL;
        if (ge_512_256(r, m)) sub_m_512(r, m);
    }
    for (int i = 0; i < 4; ++i) out[i] = r[i];
}
}  // namespace detail

// d = (a*b + c) mod m, software.
inline void fp_muladd_mod(const Fp& a, const Fp& b, const Fp& c, const Fp& m, Fp& d) {
    uint64_t t[8]; detail::mul4(a.c, b.c, t);
    unsigned __int128 carry = 0;  // t += c
    for (int i = 0; i < 8; ++i) {
        uint64_t ci = (i < 4) ? c.c[i] : 0;
        unsigned __int128 s = (unsigned __int128)t[i] + ci + carry;
        t[i] = (uint64_t)s; carry = s >> 64;
    }
    detail::mod512(t, m.c, d.c);
}

// 1/x mod p via Fermat (x^(p-2)); software stand-in for the fcall hint.
inline Fp fcall_fp_inv(const Fp& x) {
    uint64_t e[4]; std::memcpy(e, FP_P.c, sizeof(e)); e[0] -= 2;  // p-2 (p[0] odd)
    Fp res = FP_ONE;
    for (int i = 255; i >= 0; --i) {
        Fp t; fp_muladd_mod(res, res, FP_ZERO, FP_P, t); res = t;  // square
        if ((e[i >> 6] >> (i & 63)) & 1ULL) { fp_muladd_mod(res, x, FP_ZERO, FP_P, t); res = t; }
    }
    return res;
}

#endif  // backend

// ===========================================================================
// Fp ops (shared) — all expressed through fp_muladd_mod, like zisklib fp.rs.
// ===========================================================================
inline Fp fp_add(const Fp& x, const Fp& y) { Fp d; fp_muladd_mod(x, FP_ONE, y, FP_P, d); return d; }            // x*1 + y
inline Fp fp_sub(const Fp& x, const Fp& y) { Fp d; fp_muladd_mod(y, FP_P_MINUS_ONE, x, FP_P, d); return d; }     // y*(-1) + x
inline Fp fp_neg(const Fp& x) { Fp d; fp_muladd_mod(x, FP_P_MINUS_ONE, FP_ZERO, FP_P, d); return d; }
inline Fp fp_mul(const Fp& x, const Fp& y) { Fp d; fp_muladd_mod(x, y, FP_ZERO, FP_P, d); return d; }
inline Fp fp_sqr(const Fp& x) { Fp d; fp_muladd_mod(x, x, FP_ZERO, FP_P, d); return d; }

// 1/x mod p (0 ↦ 0). Hint then verify x·inv == 1.
inline Fp fp_inv(const Fp& x) {
    if (fp_is_zero(x)) return x;
    Fp inv = fcall_fp_inv(x);
    Fp chk; fp_muladd_mod(x, inv, FP_ZERO, FP_P, chk);
    if (!fp_eq(chk, FP_ONE)) { for (;;) {} }  // bad hint: must never happen
    return inv;
}

// 32-byte big-endian → Fp (little-endian limbs).
inline Fp fp_from_bytes_be(const uint8_t b[32]) {
    Fp r = FP_ZERO;
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 8; ++j)
            r.c[3 - i] |= (uint64_t)b[i * 8 + j] << (8 * (7 - j));
    return r;
}
inline void fp_to_bytes_be(const Fp& x, uint8_t b[32]) {
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 8; ++j)
            b[i * 8 + j] = (uint8_t)(x.c[3 - i] >> (8 * (7 - j)));
}

} // namespace zeg::bn

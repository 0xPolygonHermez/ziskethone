// eip2537.hpp — EIP-2537 BLS12-381 precompile encoding/validation + G1/G2 add.
//
// Shared helpers for the bls12_381_eip2537.cpp TU. Field elements are 64-byte
// big-endian with the top 16 bytes zero (value < p); G1 = x‖y (128 B), G2 =
// x.c0‖x.c1‖y.c0‖y.c1 (256 B); the all-zero point encodes infinity. Built on the
// existing G1/G2 layers from the KZG port. Faithful to evmone bls.cpp's
// validate_fp/validate_p1/validate_p2/store and EIP-2537.

#pragma once

#include "g1.hpp"
#include "g2.hpp"

namespace zeg::bls {

// 64-byte EIP-2537 field element → Fp. Returns false if top 16 bytes nonzero or value ≥ p.
inline bool fp_parse(const uint8_t b[64], Fp* out) {
    for (int i = 0; i < 16; ++i) if (b[i] != 0) return false;
    Fp x = fp_from_bytes_be(b + 16);
    if (!fp_lt(x, FP_P)) return false;
    *out = x; return true;
}
inline void fp_store(const Fp& x, uint8_t out[64]) {
    for (int i = 0; i < 16; ++i) out[i] = 0;
    fp_to_bytes_be(x, out + 16);
}
inline bool fp2_parse(const uint8_t b[128], Fp2* out) {
    return fp_parse(b, &out->c0) && fp_parse(b + 64, &out->c1);  // c0 ‖ c1
}
inline void fp2_store(const Fp2& x, uint8_t out[128]) { fp_store(x.c0, out); fp_store(x.c1, out + 64); }

// G1 point: x‖y (128 B). All-zero ⇒ infinity. Validates in-field + on-curve.
inline bool g1_parse(const uint8_t x[64], const uint8_t y[64], G1* out) {
    Fp px, py;
    if (!fp_parse(x, &px) || !fp_parse(y, &py)) return false;
    if (fp_is_zero(px) && fp_is_zero(py)) { *out = G1_IDENTITY; return true; }
    G1 p{px, py};
    if (!g1_is_on_curve(p)) return false;
    *out = p; return true;
}
inline void g1_store(const G1& p, uint8_t rx[64], uint8_t ry[64]) {
    if (g1_is_identity(p)) { for (int i=0;i<64;++i){ rx[i]=0; ry[i]=0; } return; }
    fp_store(p.x, rx); fp_store(p.y, ry);
}
// G2 point: x(Fp2)‖y(Fp2) (256 B). All-zero ⇒ infinity.
inline bool g2_parse(const uint8_t x[128], const uint8_t y[128], G2* out) {
    Fp2 px, py;
    if (!fp2_parse(x, &px) || !fp2_parse(y, &py)) return false;
    if (fp2_is_zero(px) && fp2_is_zero(py)) { *out = G2_IDENTITY; return true; }
    G2 p{px, py};
    if (!g2_is_on_curve(p)) return false;
    *out = p; return true;
}
inline void g2_store(const G2& p, uint8_t rx[128], uint8_t ry[128]) {
    if (g2_is_identity(p)) { for (int i=0;i<128;++i){ rx[i]=0; ry[i]=0; } return; }
    fp2_store(p.x, rx); fp2_store(p.y, ry);
}

} // namespace zeg::bls

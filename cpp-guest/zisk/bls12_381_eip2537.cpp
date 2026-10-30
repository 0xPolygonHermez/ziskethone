// bls12_381_eip2537.cpp — EIP-2537 BLS12-381 precompiles (0x0b–0x11) for ZisK,
// through the EF zkVM accelerator ABI. Provides the evmone::crypto::bls symbols the
// precompile dispatch calls, each as zkvm_bls12_* calls. Replaces evmone's bls.cpp.
//
// The guest uses the EIP-2537 encoding (each Fp 64 bytes = 16 zero bytes + 48-byte
// big-endian element, x and y passed apart); the EF ABI takes packed 48-byte
// elements. bls12_381/zkvm_marshal.hpp repacks, and fails on a non-zero pad, which
// EIP-2537 requires to be an error. Validation of the points themselves (in the
// field, on the curve, in the subgroup where EIP-2537 asks for it) is the ABI's.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <evmone_precompiles/bls.hpp>   // declarations
#include "bls12_381/zkvm_marshal.hpp"
#include "zkvm_accelerators.h"

namespace evmone::crypto::bls {

using namespace zkvm_bls_marshal;

namespace {
constexpr size_t G1_MUL_IN = 160, G2_MUL_IN = 288;  // per-entry MSM sizes
// The EF arrays are packed: no padding between or inside their elements.
static_assert(sizeof(zkvm_bls12_381_g1_msm_pair) == 96 + 32);
static_assert(sizeof(zkvm_bls12_381_g2_msm_pair) == 192 + 32);
static_assert(sizeof(zkvm_bls12_381_pairing_pair) == 96 + 192);
}  // namespace

// ---- G1 / G2 addition (no subgroup check, per EIP-2537) ----------------------
bool g1_add(uint8_t rx[64], uint8_t ry[64], const uint8_t x0[64], const uint8_t y0[64],
            const uint8_t x1[64], const uint8_t y1[64]) noexcept {
    zkvm_bls12_381_g1_point a, b, r;
    if (!pack_g1(x0, y0, a.data) || !pack_g1(x1, y1, b.data)) return false;
    if (zkvm_bls12_g1_add(&a, &b, &r) != ZKVM_EOK) return false;
    unpack_g1(r.data, rx, ry);
    return true;
}
bool g2_add(uint8_t rx[128], uint8_t ry[128], const uint8_t x0[128], const uint8_t y0[128],
            const uint8_t x1[128], const uint8_t y1[128]) noexcept {
    zkvm_bls12_381_g2_point a, b, r;
    if (!pack_g2(x0, y0, a.data) || !pack_g2(x1, y1, b.data)) return false;
    if (zkvm_bls12_g2_add(&a, &b, &r) != ZKVM_EOK) return false;
    unpack_g2(r.data, rx, ry);
    return true;
}

// ---- G1 / G2 MSM: Σ[kᵢ]Pᵢ, validating each point's subgroup (per EIP-2537) ----
bool g1_msm(uint8_t rx[64], uint8_t ry[64], const uint8_t* xycs, size_t size) {
    if (size == 0 || size % G1_MUL_IN != 0) return false;
    const size_t n = size / G1_MUL_IN;
    // EF pair = { g1_point[96], scalar[32] }; guest entry = x[64] y[64] scalar[32].
    std::vector<zkvm_bls12_381_g1_msm_pair> pairs(n);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = xycs + i * G1_MUL_IN;
        if (!pack_g1(e, e + 64, pairs[i].point.data)) return false;
        std::memcpy(pairs[i].scalar.data, e + 128, 32);
    }
    zkvm_bls12_381_g1_point r;
    if (zkvm_bls12_g1_msm(pairs.data(), n, &r) != ZKVM_EOK) return false;
    unpack_g1(r.data, rx, ry);
    return true;
}
bool g2_msm(uint8_t rx[128], uint8_t ry[128], const uint8_t* xycs, size_t size) {
    if (size == 0 || size % G2_MUL_IN != 0) return false;
    const size_t n = size / G2_MUL_IN;
    // EF pair = { g2_point[192], scalar[32] }; guest entry = x[128] y[128] scalar[32].
    std::vector<zkvm_bls12_381_g2_msm_pair> pairs(n);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = xycs + i * G2_MUL_IN;
        if (!pack_g2(e, e + 128, pairs[i].point.data)) return false;
        std::memcpy(pairs[i].scalar.data, e + 256, 32);
    }
    zkvm_bls12_381_g2_point r;
    if (zkvm_bls12_g2_msm(pairs.data(), n, &r) != ZKVM_EOK) return false;
    unpack_g2(r.data, rx, ry);
    return true;
}

// ---- G1 / G2 scalar mul: the one-pair MSM (evmone's single-entry shortcut) -----
// The EF ABI has no separate mul; a one-pair MSM does the same checks (identity
// maps to identity, otherwise the point must be in the subgroup).
bool g1_mul(uint8_t rx[64], uint8_t ry[64], const uint8_t x[64], const uint8_t y[64],
            const uint8_t scalar[32]) noexcept {
    zkvm_bls12_381_g1_msm_pair pair;
    zkvm_bls12_381_g1_point r;
    if (!pack_g1(x, y, pair.point.data)) return false;
    std::memcpy(pair.scalar.data, scalar, 32);
    if (zkvm_bls12_g1_msm(&pair, 1, &r) != ZKVM_EOK) return false;
    unpack_g1(r.data, rx, ry);
    return true;
}
bool g2_mul(uint8_t rx[128], uint8_t ry[128], const uint8_t x[128], const uint8_t y[128],
            const uint8_t scalar[32]) noexcept {
    zkvm_bls12_381_g2_msm_pair pair;
    zkvm_bls12_381_g2_point r;
    if (!pack_g2(x, y, pair.point.data)) return false;
    std::memcpy(pair.scalar.data, scalar, 32);
    if (zkvm_bls12_g2_msm(&pair, 1, &r) != ZKVM_EOK) return false;
    unpack_g2(r.data, rx, ry);
    return true;
}

// ---- map-to-curve (SWU + isogeny + cofactor clear) --------------------------
bool map_fp_to_g1(uint8_t rx[64], uint8_t ry[64], const uint8_t fp[64]) noexcept {
    zkvm_bls12_381_fp ef;
    zkvm_bls12_381_g1_point r;
    if (!pack_fp(fp, ef.data)) return false;
    if (zkvm_bls12_map_fp_to_g1(&ef, &r) != ZKVM_EOK) return false;
    unpack_g1(r.data, rx, ry);
    return true;
}
bool map_fp2_to_g2(uint8_t rx[128], uint8_t ry[128], const uint8_t fp[128]) noexcept {
    // Fp2 = c0||c1, each guest [16 zero | 48 BE]; EF fp2 = c0[48] || c1[48].
    zkvm_bls12_381_fp2 ef;
    zkvm_bls12_381_g2_point r;
    if (!pack_fp(fp, ef.data) || !pack_fp(fp + 64, ef.data + 48)) return false;
    if (zkvm_bls12_map_fp2_to_g2(&ef, &r) != ZKVM_EOK) return false;
    unpack_g2(r.data, rx, ry);
    return true;
}

// ---- pairing check: Π e(Pᵢ,Qᵢ) == 1 ----------------------------------------
bool pairing_check(uint8_t r[32], const uint8_t* pairs, size_t size) noexcept {
    constexpr size_t PAIR = 384;  // G1 (128) + G2 (256)
    if (size % PAIR != 0) return false;
    const size_t n = size / PAIR;
    // EF pair = { g1_point[96], g2_point[192] } = 288 bytes.
    std::vector<zkvm_bls12_381_pairing_pair> ef(n);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = pairs + i * PAIR;
        if (!pack_g1(e, e + 64, ef[i].g1.data) || !pack_g2(e + 128, e + 256, ef[i].g2.data))
            return false;
    }
    bool ok = false;
    if (zkvm_bls12_pairing(ef.data(), n, &ok) != ZKVM_EOK) return false;
    std::memset(r, 0, 32);
    r[31] = ok ? 1 : 0;
    return true;
}

}  // namespace evmone::crypto::bls

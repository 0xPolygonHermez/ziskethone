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
constexpr size_t EF_G1_PAIR = 96 + 32, EF_G2_PAIR = 192 + 32;
}  // namespace

// ---- G1 / G2 addition (no subgroup check, per EIP-2537) ----------------------
bool g1_add(uint8_t rx[64], uint8_t ry[64], const uint8_t x0[64], const uint8_t y0[64],
            const uint8_t x1[64], const uint8_t y1[64]) noexcept {
    uint8_t a[96], b[96], r[96];
    if (!pack_g1(x0, y0, a) || !pack_g1(x1, y1, b)) return false;
    if (zkvm_bls12_g1_add(reinterpret_cast<const zkvm_bls12_381_g1_point*>(a),
                          reinterpret_cast<const zkvm_bls12_381_g1_point*>(b),
                          reinterpret_cast<zkvm_bls12_381_g1_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g1(r, rx, ry);
    return true;
}
bool g2_add(uint8_t rx[128], uint8_t ry[128], const uint8_t x0[128], const uint8_t y0[128],
            const uint8_t x1[128], const uint8_t y1[128]) noexcept {
    uint8_t a[192], b[192], r[192];
    if (!pack_g2(x0, y0, a) || !pack_g2(x1, y1, b)) return false;
    if (zkvm_bls12_g2_add(reinterpret_cast<const zkvm_bls12_381_g2_point*>(a),
                          reinterpret_cast<const zkvm_bls12_381_g2_point*>(b),
                          reinterpret_cast<zkvm_bls12_381_g2_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g2(r, rx, ry);
    return true;
}

// ---- G1 / G2 MSM: Σ[kᵢ]Pᵢ, validating each point's subgroup (per EIP-2537) ----
bool g1_msm(uint8_t rx[64], uint8_t ry[64], const uint8_t* xycs, size_t size) {
    if (size == 0 || size % G1_MUL_IN != 0) return false;
    const size_t n = size / G1_MUL_IN;
    // EF pair = { g1_point[96], scalar[32] }; guest entry = x[64] y[64] scalar[32].
    std::vector<uint8_t> pairs(n * EF_G1_PAIR);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = xycs + i * G1_MUL_IN;
        uint8_t* d = pairs.data() + i * EF_G1_PAIR;
        if (!pack_g1(e, e + 64, d)) return false;
        std::memcpy(d + 96, e + 128, 32);
    }
    uint8_t r[96];
    if (zkvm_bls12_g1_msm(reinterpret_cast<const zkvm_bls12_381_g1_msm_pair*>(pairs.data()), n,
                          reinterpret_cast<zkvm_bls12_381_g1_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g1(r, rx, ry);
    return true;
}
bool g2_msm(uint8_t rx[128], uint8_t ry[128], const uint8_t* xycs, size_t size) {
    if (size == 0 || size % G2_MUL_IN != 0) return false;
    const size_t n = size / G2_MUL_IN;
    // EF pair = { g2_point[192], scalar[32] }; guest entry = x[128] y[128] scalar[32].
    std::vector<uint8_t> pairs(n * EF_G2_PAIR);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = xycs + i * G2_MUL_IN;
        uint8_t* d = pairs.data() + i * EF_G2_PAIR;
        if (!pack_g2(e, e + 128, d)) return false;
        std::memcpy(d + 192, e + 256, 32);
    }
    uint8_t r[192];
    if (zkvm_bls12_g2_msm(reinterpret_cast<const zkvm_bls12_381_g2_msm_pair*>(pairs.data()), n,
                          reinterpret_cast<zkvm_bls12_381_g2_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g2(r, rx, ry);
    return true;
}

// ---- G1 / G2 scalar mul: the one-pair MSM (evmone's single-entry shortcut) -----
// The EF ABI has no separate mul; a one-pair MSM does the same checks (identity
// maps to identity, otherwise the point must be in the subgroup).
bool g1_mul(uint8_t rx[64], uint8_t ry[64], const uint8_t x[64], const uint8_t y[64],
            const uint8_t scalar[32]) noexcept {
    uint8_t pair[EF_G1_PAIR], r[96];
    if (!pack_g1(x, y, pair)) return false;
    std::memcpy(pair + 96, scalar, 32);
    if (zkvm_bls12_g1_msm(reinterpret_cast<const zkvm_bls12_381_g1_msm_pair*>(pair), 1,
                          reinterpret_cast<zkvm_bls12_381_g1_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g1(r, rx, ry);
    return true;
}
bool g2_mul(uint8_t rx[128], uint8_t ry[128], const uint8_t x[128], const uint8_t y[128],
            const uint8_t scalar[32]) noexcept {
    uint8_t pair[EF_G2_PAIR], r[192];
    if (!pack_g2(x, y, pair)) return false;
    std::memcpy(pair + 192, scalar, 32);
    if (zkvm_bls12_g2_msm(reinterpret_cast<const zkvm_bls12_381_g2_msm_pair*>(pair), 1,
                          reinterpret_cast<zkvm_bls12_381_g2_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g2(r, rx, ry);
    return true;
}

// ---- map-to-curve (SWU + isogeny + cofactor clear) --------------------------
bool map_fp_to_g1(uint8_t rx[64], uint8_t ry[64], const uint8_t fp[64]) noexcept {
    uint8_t ef[48], r[96];
    if (!pack_fp(fp, ef)) return false;
    if (zkvm_bls12_map_fp_to_g1(reinterpret_cast<const zkvm_bls12_381_fp*>(ef),
                                reinterpret_cast<zkvm_bls12_381_g1_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g1(r, rx, ry);
    return true;
}
bool map_fp2_to_g2(uint8_t rx[128], uint8_t ry[128], const uint8_t fp[128]) noexcept {
    // Fp2 = c0||c1, each guest [16 zero | 48 BE]; EF fp2 = c0[48] || c1[48].
    uint8_t ef[96], r[192];
    if (!pack_fp(fp, ef) || !pack_fp(fp + 64, ef + 48)) return false;
    if (zkvm_bls12_map_fp2_to_g2(reinterpret_cast<const zkvm_bls12_381_fp2*>(ef),
                                 reinterpret_cast<zkvm_bls12_381_g2_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g2(r, rx, ry);
    return true;
}

// ---- pairing check: Π e(Pᵢ,Qᵢ) == 1 ----------------------------------------
bool pairing_check(uint8_t r[32], const uint8_t* pairs, size_t size) noexcept {
    constexpr size_t PAIR = 384;  // G1 (128) + G2 (256)
    if (size % PAIR != 0) return false;
    const size_t n = size / PAIR;
    // EF pair = { g1_point[96], g2_point[192] } = 288 bytes.
    std::vector<uint8_t> ef(n * 288);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = pairs + i * PAIR;
        uint8_t* d = ef.data() + i * 288;
        if (!pack_g1(e, e + 64, d) || !pack_g2(e + 128, e + 256, d + 96)) return false;
    }
    bool ok = false;
    if (zkvm_bls12_pairing(reinterpret_cast<const zkvm_bls12_381_pairing_pair*>(ef.data()), n,
                           &ok) != ZKVM_EOK)
        return false;
    std::memset(r, 0, 32);
    r[31] = ok ? 1 : 0;
    return true;
}

}  // namespace evmone::crypto::bls

// bls12_381_eip2537.cpp — EIP-2537 BLS12-381 precompiles (0x0b–0x11) for ZisK.
// Provides the evmone::crypto::bls symbols the precompile dispatch calls, on the
// self-contained BLS12-381 port (bls12_381/) running on the ZisK precompiles +
// fcall hints. Replaces the failure stubs in precompile_stubs.cpp.
//
// Implemented incrementally: g1_add/g2_add first; mul/msm/pairing_check/map are
// filled in by later layers (return false until then).

#include <cstddef>
#include <cstdint>

#include <evmone_precompiles/bls.hpp>   // declarations
#include "bls12_381/eip2537.hpp"
#include "bls12_381/g2_subgroup.hpp"
#include "bls12_381/map_to_curve.hpp"
#ifdef ZKVM_BLS
#include <vector>
#include "zkvm_accelerators.h"
#include "bls12_381/zkvm_marshal.hpp"   // pack/unpack between EIP-2537 64B and EF 48B
#endif

namespace evmone::crypto::bls {

using namespace zeg::bls;

namespace {
constexpr int G1_MUL_IN = 160, G2_MUL_IN = 288;  // per-entry MSM sizes
}

// ---- G1 / G2 addition (no subgroup check, per EIP-2537) ----------------------
bool g1_add(uint8_t rx[64], uint8_t ry[64], const uint8_t x0[64], const uint8_t y0[64],
            const uint8_t x1[64], const uint8_t y1[64]) noexcept {
#ifdef ZKVM_BLS
    using namespace zkvm_bls_marshal;
    uint8_t a[96], b[96], r[96];
    pack_g1(x0, y0, a);
    pack_g1(x1, y1, b);
    if (zkvm_bls12_g1_add(reinterpret_cast<const zkvm_bls12_381_g1_point*>(a),
                          reinterpret_cast<const zkvm_bls12_381_g1_point*>(b),
                          reinterpret_cast<zkvm_bls12_381_g1_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g1(r, rx, ry);
    return true;
#else
    G1 a, b;
    if (!g1_parse(x0, y0, &a) || !g1_parse(x1, y1, &b)) return false;
    g1_store(g1_add_complete(a, b), rx, ry);
    return true;
#endif
}
bool g2_add(uint8_t rx[128], uint8_t ry[128], const uint8_t x0[128], const uint8_t y0[128],
            const uint8_t x1[128], const uint8_t y1[128]) noexcept {
#ifdef ZKVM_BLS
    using namespace zkvm_bls_marshal;
    uint8_t a[192], b[192], r[192];
    pack_g2(x0, y0, a);
    pack_g2(x1, y1, b);
    if (zkvm_bls12_g2_add(reinterpret_cast<const zkvm_bls12_381_g2_point*>(a),
                          reinterpret_cast<const zkvm_bls12_381_g2_point*>(b),
                          reinterpret_cast<zkvm_bls12_381_g2_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g2(r, rx, ry);
    return true;
#else
    G2 a, b;
    if (!g2_parse(x0, y0, &a) || !g2_parse(x1, y1, &b)) return false;
    g2_store(g2_add_complete(a, b), rx, ry);
    return true;
#endif
}

// ---- G1 / G2 scalar mul (validates subgroup, per EIP-2537) -------------------
bool g1_mul(uint8_t rx[64], uint8_t ry[64], const uint8_t x[64], const uint8_t y[64],
            const uint8_t scalar[32]) noexcept {
    G1 p;
    if (!g1_parse(x, y, &p)) return false;
    if (g1_is_identity(p)) { g1_store(G1_IDENTITY, rx, ry); return true; }
    if (!g1_is_on_subgroup(p)) return false;
    uint64_t k[4]; scalar_be32(scalar, k);
    g1_store(g1_scalar_mul(p, k), rx, ry);
    return true;
}
bool g2_mul(uint8_t rx[128], uint8_t ry[128], const uint8_t x[128], const uint8_t y[128],
            const uint8_t scalar[32]) noexcept {
    G2 p;
    if (!g2_parse(x, y, &p)) return false;
    if (g2_is_identity(p)) { g2_store(G2_IDENTITY, rx, ry); return true; }
    if (!g2_is_on_subgroup(p)) return false;
    uint64_t k[4]; scalar_be32(scalar, k);
    g2_store(g2_scalar_mul(p, k), rx, ry);
    return true;
}

// ---- G1 / G2 MSM: naive Σ[kᵢ]Pᵢ with per-point validation -------------------
bool g1_msm(uint8_t rx[64], uint8_t ry[64], const uint8_t* xycs, size_t size) {
    if (size == 0 || size % G1_MUL_IN != 0) return false;
    size_t n = size / G1_MUL_IN;
#ifdef ZKVM_BLS
    using namespace zkvm_bls_marshal;
    // EF pair = { g1_point[96], scalar[32] } = 128 bytes; guest entry = x[64] y[64] scalar[32].
    std::vector<uint8_t> pairs(n * 128);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = xycs + i * G1_MUL_IN;
        uint8_t* d = pairs.data() + i * 128;
        pack_g1(e, e + 64, d);
        std::memcpy(d + 96, e + 128, 32);
    }
    uint8_t r[96];
    if (zkvm_bls12_g1_msm(reinterpret_cast<const zkvm_bls12_381_g1_msm_pair*>(pairs.data()), n,
                          reinterpret_cast<zkvm_bls12_381_g1_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g1(r, rx, ry);
    return true;
#else
    G1 acc = G1_IDENTITY;
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = xycs + i * G1_MUL_IN;
        G1 p;
        if (!g1_parse(e, e + 64, &p)) return false;
        if (g1_is_identity(p)) continue;
        if (!g1_is_on_subgroup(p)) return false;
        uint64_t k[4]; scalar_be32(e + 128, k);
        G1 prod = g1_scalar_mul(p, k);
        if (g1_is_identity(prod)) continue;
        acc = g1_is_identity(acc) ? prod : g1_add_complete(acc, prod);
    }
    g1_store(acc, rx, ry);
    return true;
#endif
}
bool g2_msm(uint8_t rx[128], uint8_t ry[128], const uint8_t* xycs, size_t size) {
    if (size == 0 || size % G2_MUL_IN != 0) return false;
    size_t n = size / G2_MUL_IN;
#ifdef ZKVM_BLS
    using namespace zkvm_bls_marshal;
    // EF pair = { g2_point[192], scalar[32] } = 224 bytes; guest entry = x[128] y[128] scalar[32].
    std::vector<uint8_t> pairs(n * 224);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = xycs + i * G2_MUL_IN;
        uint8_t* d = pairs.data() + i * 224;
        pack_g2(e, e + 128, d);
        std::memcpy(d + 192, e + 256, 32);
    }
    uint8_t r[192];
    if (zkvm_bls12_g2_msm(reinterpret_cast<const zkvm_bls12_381_g2_msm_pair*>(pairs.data()), n,
                          reinterpret_cast<zkvm_bls12_381_g2_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g2(r, rx, ry);
    return true;
#else
    G2 acc = G2_IDENTITY;
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = xycs + i * G2_MUL_IN;
        G2 p;
        if (!g2_parse(e, e + 128, &p)) return false;
        if (g2_is_identity(p)) continue;
        if (!g2_is_on_subgroup(p)) return false;
        uint64_t k[4]; scalar_be32(e + 256, k);
        G2 prod = g2_scalar_mul(p, k);
        if (g2_is_identity(prod)) continue;
        acc = g2_is_identity(acc) ? prod : g2_add_complete(acc, prod);
    }
    g2_store(acc, rx, ry);
    return true;
#endif
}

// ---- map-to-curve (SWU + isogeny + cofactor clear) --------------------------
bool map_fp_to_g1(uint8_t rx[64], uint8_t ry[64], const uint8_t fp[64]) noexcept {
#ifdef ZKVM_BLS
    using namespace zkvm_bls_marshal;
    uint8_t ef[48], r[96];
    pack_fp(fp, ef);
    if (zkvm_bls12_map_fp_to_g1(reinterpret_cast<const zkvm_bls12_381_fp*>(ef),
                                reinterpret_cast<zkvm_bls12_381_g1_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g1(r, rx, ry);
    return true;
#else
    Fp u;
    if (!fp_parse(fp, &u)) return false;  // validates top-16-zero + < p
    g1_store(map_to_curve_g1(u), rx, ry);
    return true;
#endif
}
bool map_fp2_to_g2(uint8_t rx[128], uint8_t ry[128], const uint8_t fp[128]) noexcept {
#ifdef ZKVM_BLS
    using namespace zkvm_bls_marshal;
    // Fp2 = c0||c1, each guest [16 zero | 48 BE]; EF fp2 = c0[48] || c1[48].
    uint8_t ef[96], r[192];
    pack_fp(fp, ef);
    pack_fp(fp + 64, ef + 48);
    if (zkvm_bls12_map_fp2_to_g2(reinterpret_cast<const zkvm_bls12_381_fp2*>(ef),
                                 reinterpret_cast<zkvm_bls12_381_g2_point*>(r)) != ZKVM_EOK)
        return false;
    unpack_g2(r, rx, ry);
    return true;
#else
    Fp2 u;
    if (!fp2_parse(fp, &u)) return false;
    g2_store(map_to_curve_g2(u), rx, ry);
    return true;
#endif
}

// ---- pairing check: Π e(Pᵢ,Qᵢ) == 1 ----------------------------------------
// Per-pair validate (in-field, on-curve, subgroup), skip ∞ pairs, batch the
// Miller loops, then one final_exp. Mirrors evmone bls.cpp pairing_check.
bool pairing_check(uint8_t r[32], const uint8_t* pairs, size_t size) noexcept {
    constexpr int PAIR = 384;  // G1 (128) + G2 (256)
    if (size % PAIR != 0) return false;
    size_t n = size / PAIR;
#ifdef ZKVM_BLS
    using namespace zkvm_bls_marshal;
    // EF pair = { g1_point[96], g2_point[192] } = 288 bytes.
    std::vector<uint8_t> ef(n * 288);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = pairs + i * PAIR;
        uint8_t* d = ef.data() + i * 288;
        pack_g1(e, e + 64, d);              // G1 (x,y)
        pack_g2(e + 128, e + 256, d + 96);  // G2 (x,y)
    }
    bool ok = false;
    if (zkvm_bls12_pairing(reinterpret_cast<const zkvm_bls12_381_pairing_pair*>(ef.data()), n,
                           &ok) != ZKVM_EOK)
        return false;
    for (int i = 0; i < 32; ++i) r[i] = 0;
    r[31] = ok ? 1 : 0;
    return true;
#else
    Fp12 acc = FP12_ONE;
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = pairs + i * PAIR;
        G1 p; G2 q;
        if (!g1_parse(e, e + 64, &p)) return false;
        if (!g2_parse(e + 128, e + 256, &q)) return false;
        if (!g1_is_identity(p) && !g1_is_on_subgroup(p)) return false;
        if (!g2_is_identity(q) && !g2_is_on_subgroup(q)) return false;
        if (g1_is_identity(p) || g2_is_identity(q)) continue;  // pair contributes 1
        acc = fp12_mul(acc, miller_loop(p, q));
    }
    bool one = fp12_is_one(final_exp(acc));
    for (int i = 0; i < 32; ++i) r[i] = 0;
    r[31] = one ? 1 : 0;
    return true;
#endif
}

}  // namespace evmone::crypto::bls

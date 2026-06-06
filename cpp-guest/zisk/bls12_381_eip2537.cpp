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

namespace evmone::crypto::bls {

using namespace zeg::bls;

namespace {
constexpr int G1_MUL_IN = 160, G2_MUL_IN = 288;  // per-entry MSM sizes
}

// ---- G1 / G2 addition (no subgroup check, per EIP-2537) ----------------------
bool g1_add(uint8_t rx[64], uint8_t ry[64], const uint8_t x0[64], const uint8_t y0[64],
            const uint8_t x1[64], const uint8_t y1[64]) noexcept {
    G1 a, b;
    if (!g1_parse(x0, y0, &a) || !g1_parse(x1, y1, &b)) return false;
    g1_store(g1_add_complete(a, b), rx, ry);
    return true;
}
bool g2_add(uint8_t rx[128], uint8_t ry[128], const uint8_t x0[128], const uint8_t y0[128],
            const uint8_t x1[128], const uint8_t y1[128]) noexcept {
    G2 a, b;
    if (!g2_parse(x0, y0, &a) || !g2_parse(x1, y1, &b)) return false;
    g2_store(g2_add_complete(a, b), rx, ry);
    return true;
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
}
bool g2_msm(uint8_t rx[128], uint8_t ry[128], const uint8_t* xycs, size_t size) {
    if (size == 0 || size % G2_MUL_IN != 0) return false;
    size_t n = size / G2_MUL_IN;
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
}

// ---- placeholders (filled by later layers) -----------------------------------
bool map_fp_to_g1(uint8_t[64], uint8_t[64], const uint8_t[64]) noexcept { return false; }
bool map_fp2_to_g2(uint8_t[128], uint8_t[128], const uint8_t[128]) noexcept { return false; }
bool pairing_check(uint8_t[32], const uint8_t*, size_t) noexcept { return false; }

}  // namespace evmone::crypto::bls

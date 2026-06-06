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

namespace evmone::crypto::bls {

using namespace zeg::bls;

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

// ---- placeholders (filled by later layers) -----------------------------------
bool g1_mul(uint8_t[64], uint8_t[64], const uint8_t[64], const uint8_t[64],
            const uint8_t[32]) noexcept { return false; }
bool g2_mul(uint8_t[128], uint8_t[128], const uint8_t[128], const uint8_t[128],
            const uint8_t[32]) noexcept { return false; }
bool g1_msm(uint8_t[64], uint8_t[64], const uint8_t*, size_t) { return false; }
bool g2_msm(uint8_t[128], uint8_t[128], const uint8_t*, size_t) { return false; }
bool map_fp_to_g1(uint8_t[64], uint8_t[64], const uint8_t[64]) noexcept { return false; }
bool map_fp2_to_g2(uint8_t[128], uint8_t[128], const uint8_t[128]) noexcept { return false; }
bool pairing_check(uint8_t[32], const uint8_t*, size_t) noexcept { return false; }

}  // namespace evmone::crypto::bls

// precompile_stubs.cpp — failure stubs for the EIP-2537 (BLS12-381) precompiles.
//
// evmone's bls.cpp pulls in blst (hand-written x86/arm assembly), which doesn't
// cross-compile to rv64ima; that TU is excluded and these stubs stand in, so any
// block that DOESN'T use the EIP-2537 BLS precompiles runs unaffected. A block
// that does use them will mismatch until they're implemented on ZisK. (Keccak,
// secp256k1, KZG point-eval and MODEXP are already done — no stubs.)

#include <cstddef>
#include <cstdint>
#include <span>

// MODEXP (0x05) is implemented for real in modexp_zisk.cpp (arbitrary-precision
// modular exponentiation on the ZisK arith256/add256 precompiles + fcalls);
// no stub here anymore.

namespace evmone::crypto::bls {

bool g1_add(uint8_t[64], uint8_t[64], const uint8_t[64], const uint8_t[64],
            const uint8_t[64], const uint8_t[64]) noexcept { return false; }
bool g1_mul(uint8_t[64], uint8_t[64], const uint8_t[64], const uint8_t[64],
            const uint8_t[32]) noexcept { return false; }
bool g2_add(uint8_t[128], uint8_t[128], const uint8_t[128], const uint8_t[128],
            const uint8_t[128], const uint8_t[128]) noexcept { return false; }
bool g2_mul(uint8_t[128], uint8_t[128], const uint8_t[128], const uint8_t[128],
            const uint8_t[32]) noexcept { return false; }
bool g1_msm(uint8_t[64], uint8_t[64], const uint8_t*, size_t) { return false; }
bool g2_msm(uint8_t[128], uint8_t[128], const uint8_t*, size_t) { return false; }
bool map_fp_to_g1(uint8_t[64], uint8_t[64], const uint8_t[64]) noexcept { return false; }
bool map_fp2_to_g2(uint8_t[128], uint8_t[128], const uint8_t[128]) noexcept { return false; }
bool pairing_check(uint8_t[32], const uint8_t*, size_t) noexcept { return false; }

}  // namespace evmone::crypto::bls

// KZG point-evaluation (0x0a) is implemented for real in bls12_381_kzg.cpp
// (BLS12-381 pairing on the ZisK precompiles + fcalls); no stub here anymore.

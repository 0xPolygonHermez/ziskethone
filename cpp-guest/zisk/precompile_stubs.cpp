// precompile_stubs.cpp — failure stubs for the EIP-2537 (BLS12-381) and
// EIP-4844 (KZG point-evaluation) precompiles.
//
// bls.cpp pulls in blst (hand-written x86/arm assembly) and kzg.cpp pulls in
// c-kzg, neither of which cross-compiles to rv64ima out of the box. For the
// first ZisK build we exclude those two translation units and provide these
// stubs, so any block that DOESN'T use BLS/blob precompiles runs unaffected.
// A block that does use them will get a precompile failure (and mismatch) —
// the proving build will replace these with the ZisK bls/kzg accelerators.

#include <cstddef>
#include <cstdint>
#include <span>

namespace evmone::crypto {

// MODEXP (0x05). The real impl (modexp.cpp) uses std::pmr; excluded here.
// Zeroes the output (sized to the modulus by the caller) — wrong for a block
// that uses MODEXP, fine otherwise.
void modexp(std::span<const uint8_t>, std::span<const uint8_t>,
            std::span<const uint8_t> mod, uint8_t* output) noexcept {
    for (size_t i = 0; i < mod.size(); ++i) output[i] = 0;
}

}  // namespace evmone::crypto

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

namespace evmone::crypto {

bool kzg_verify_proof(const std::byte[32], const std::byte[32], const std::byte[32],
                      const std::byte[48], const std::byte[48]) noexcept { return false; }

}  // namespace evmone::crypto

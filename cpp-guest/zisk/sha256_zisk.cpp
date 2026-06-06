// sha256_zisk.cpp — accelerated SHA-256 for the ZisK self-contained build.
//
// Drop-in replacement for evmone's evmone_precompiles/sha256.cpp. Provides the one
// public symbol the whole guest funnels through:
//
//   void evmone::crypto::sha256(std::byte hash[32], const std::byte* data, size_t)
//
// Every SHA-256 in the guest bottoms out here — the SHA256 precompile (0x02), the
// KZG versioned hash (bls12_381_kzg.cpp), and the EIP-7685 requests hash
// (zeg::sha256_bytes32). Swapping this one symbol accelerates them all by routing
// the compression through the ZisK sha256f precompile (CSR 0x805); see
// sha256/sha256_impl.hpp. Mirrors keccak_zisk.cpp.

#include <cstddef>
#include <cstdint>

#include <evmone_precompiles/sha256.hpp>
#include "sha256/sha256_impl.hpp"

namespace evmone::crypto {

void sha256(std::byte hash[SHA256_HASH_SIZE], const std::byte* data, size_t size) {
    zeg::sh2::sha256(reinterpret_cast<uint8_t*>(hash),
                     reinterpret_cast<const uint8_t*>(data), size);
}

}  // namespace evmone::crypto

// sha256_zisk.cpp — SHA-256 for the ZisK build, through the EF zkVM accelerator ABI.
//
// Drop-in replacement for evmone's evmone_precompiles/sha256.cpp. Provides the one
// public symbol the whole guest funnels through:
//
//   void evmone::crypto::sha256(std::byte hash[32], const std::byte* data, size_t)
//
// Every SHA-256 in the guest bottoms out here — the SHA256 precompile (0x02), the
// KZG versioned hash (bls12_381_kzg.cpp), and the EIP-7685 requests hash
// (zeg::sha256_bytes32). It is one zkvm_sha256 call: a zkvmcall thunk
// (zkvm_calls.s) that the transpiler turns into a jump to the native .zisk routine.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <evmone_precompiles/sha256.hpp>
#include "zkvm_accelerators.h"

namespace evmone::crypto {

void sha256(std::byte hash[SHA256_HASH_SIZE], const std::byte* data, size_t size) {
    // The caller's hash buffer has any alignment; zkvm_sha256_hash is 8-byte aligned.
    zkvm_sha256_hash out;
    zkvm_sha256(reinterpret_cast<const uint8_t*>(data), size, &out);
    std::memcpy(hash, out.data, sizeof out.data);
}

}  // namespace evmone::crypto

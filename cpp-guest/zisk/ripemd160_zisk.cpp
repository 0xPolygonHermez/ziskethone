// ripemd160_zisk.cpp — RIPEMD-160 for the ZisK build, through the EF zkVM accelerator
// ABI. Drop-in replacement for evmone's evmone_precompiles/ripemd160.cpp (excluded
// from the build). Provides the symbol the RIPEMD160 precompile (0x03) calls:
//
//   void evmone::crypto::ripemd160(std::byte hash[20], const std::byte* data, size_t)
//
// as one zkvm_ripemd160 call. The EF ABI writes the precompile's 32-byte word, the
// 20-byte digest right-aligned after 12 zero bytes; evmone wants the digest alone.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <evmone_precompiles/ripemd160.hpp>
#include "zkvm_accelerators.h"

namespace evmone::crypto {

void ripemd160(std::byte hash[RIPEMD160_HASH_SIZE], const std::byte* data,
               std::size_t size) noexcept {
    zkvm_ripemd160_hash word;
    zkvm_ripemd160(reinterpret_cast<const uint8_t*>(data), size, &word);
    std::memcpy(hash, reinterpret_cast<const uint8_t*>(&word) + 32 - RIPEMD160_HASH_SIZE,
                RIPEMD160_HASH_SIZE);
}

}  // namespace evmone::crypto

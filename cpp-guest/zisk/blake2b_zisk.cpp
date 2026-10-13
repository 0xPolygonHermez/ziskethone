// blake2b_zisk.cpp — BLAKE2b F compression for the ZisK build, through the EF zkVM
// accelerator ABI.
//
// Drop-in replacement for evmone's evmone_precompiles/blake2b.cpp. Provides the one
// public symbol the BLAKE2 precompile (0x09, EIP-152) funnels through:
//
//   void evmone::crypto::blake2b_compress(uint32_t rounds, uint64_t h[8],
//        const uint64_t m[16], const uint64_t t[2], bool last)
//
// as one zkvm_blake2f call. h/m/t are little-endian u64 words, byte-identical to the
// zkvm_blake2f_* byte structs on little-endian RISC-V, so the casts need no
// marshalling; h is updated in place.

#include <cstdint>

#include <evmone_precompiles/blake2b.hpp>
#include "zkvm_accelerators.h"

namespace evmone::crypto {

void blake2b_compress(uint32_t rounds, uint64_t h[8], const uint64_t m[16],
                      const uint64_t t[2], bool last) noexcept {
    zkvm_blake2f(rounds, reinterpret_cast<zkvm_blake2f_state*>(h),
                 reinterpret_cast<const zkvm_blake2f_message*>(m),
                 reinterpret_cast<const zkvm_blake2f_offset*>(t),
                 static_cast<uint8_t>(last));
}

}  // namespace evmone::crypto

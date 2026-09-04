// blake2b_zisk.cpp — accelerated BLAKE2b F compression for the ZisK build.
//
// Drop-in replacement for evmone's evmone_precompiles/blake2b.cpp. Provides the one
// public symbol the BLAKE2 precompile (0x09, EIP-152) funnels through:
//
//   void evmone::crypto::blake2b_compress(uint32_t rounds, uint64_t h[8],
//        const uint64_t m[16], const uint64_t t[2], bool last)
//
// routing each mixing round through the ZisK blake2b_round precompile (CSR 0x819);
// see blake2b/blake2b_impl.hpp. Mirrors keccak_zisk.cpp / sha256_zisk.cpp.

#include <cstdint>

#include <evmone_precompiles/blake2b.hpp>
#include "blake2b/blake2b_impl.hpp"
#ifdef ZKVM_BLAKE2F
#include "zkvm_accelerators.h"
#endif

namespace evmone::crypto {

void blake2b_compress(uint32_t rounds, uint64_t h[8], const uint64_t m[16],
                      const uint64_t t[2], bool last) noexcept {
#ifdef ZKVM_BLAKE2F
    // EF standard C ABI: redirected by elf2rom to the native .zisk blake2f. The
    // EIP-152 F compression has the same (rounds, h, m, t, f) shape; h/m/t are
    // little-endian u64 words, byte-identical to the zkvm_blake2f_* byte structs
    // on little-endian RISC-V, so the casts need no marshalling. h is updated
    // in place, exactly as zeg::bk::compress does.
    zkvm_blake2f(rounds, reinterpret_cast<zkvm_blake2f_state*>(h),
                 reinterpret_cast<const zkvm_blake2f_message*>(m),
                 reinterpret_cast<const zkvm_blake2f_offset*>(t),
                 static_cast<uint8_t>(last));
#else
    zeg::bk::compress(rounds, h, m, t, last);
#endif
}

}  // namespace evmone::crypto

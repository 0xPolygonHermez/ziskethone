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

namespace evmone::crypto {

void blake2b_compress(uint32_t rounds, uint64_t h[8], const uint64_t m[16],
                      const uint64_t t[2], bool last) noexcept {
    zeg::bk::compress(rounds, h, m, t, last);
}

}  // namespace evmone::crypto

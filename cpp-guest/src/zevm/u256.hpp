// u256.hpp — the 256-bit EVM word type, shared across zevm.
//
// Little-endian limbs (limbs[0] = least significant) to match zeg::bi
// (arith256 / add256 / ...) so stack and memory values can be fed to the ZisK
// 256-bit precompiles without reshuffling. EVM words are 32 bytes; the spec's
// "32 bits" is read as 32 bytes.

#pragma once

#include <cstdint>

namespace zevm {

struct U256 {
    uint64_t limbs[4];
};

// Load a 256-bit value from 32 big-endian bytes (bytes[0] is most significant),
// the on-wire layout used by EVM code immediates (PUSH) and memory (MLOAD).
inline U256 u256_from_be(const uint8_t bytes[32]) {
    U256 v;
    for (int i = 0; i < 4; ++i) {
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j)
            w = (w << 8) | bytes[i * 8 + j];   // i == 0 -> most significant limb
        v.limbs[3 - i] = w;
    }
    return v;
}

}  // namespace zevm

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

}  // namespace zevm

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

// ----- value helpers (shared by the arithmetic / bitwise opcode handlers) -----

inline bool u256_is_zero(const U256& a) {
    return (a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]) == 0;
}

inline bool u256_eq(const U256& a, const U256& b) {
    return a.limbs[0] == b.limbs[0] && a.limbs[1] == b.limbs[1] &&
           a.limbs[2] == b.limbs[2] && a.limbs[3] == b.limbs[3];
}

// Unsigned less-than, comparing from the most significant limb down.
inline bool u256_lt(const U256& a, const U256& b) {
    for (int i = 3; i >= 0; --i)
        if (a.limbs[i] != b.limbs[i]) return a.limbs[i] < b.limbs[i];
    return false;
}

// Top (sign) bit — interprets the word as a two's-complement signed integer.
inline bool u256_sign(const U256& a) { return (a.limbs[3] >> 63) != 0; }

// Two's-complement negation: (2^256 - a) mod 2^256 == ~a + 1.
inline U256 u256_neg(const U256& a) {
    U256 r;
    uint64_t carry = 1;
    for (int i = 0; i < 4; ++i) {
        uint64_t v = ~a.limbs[i] + carry;
        carry = (v < carry) ? 1 : 0;
        r.limbs[i] = v;
    }
    return r;
}

}  // namespace zevm

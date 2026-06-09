// u256.hpp — the 256-bit EVM word type, shared across zevm.
//
// Little-endian limbs (limbs[0] = least significant) to match zeg::bi
// (arith256 / add256 / ...) so stack and memory values can be fed to the ZisK
// 256-bit precompiles without reshuffling. EVM words are 32 bytes; the spec's
// "32 bits" is read as 32 bytes.

#pragma once

#include <cstdint>
#include <cstring>  // std::memcpy

// libgcc 64-bit byte swap: soft implementation in zisk/compiler_rt.cpp on the
// ZisK target (rv64ima, no Zbb), compiler-rt builtin on the host.
extern "C" uint64_t __bswapdi2(uint64_t);

namespace zevm {

struct U256 {
    uint64_t limbs[4];
};

// Load a 256-bit value from 32 big-endian bytes (bytes[0] is most significant),
// the on-wire layout used by EVM code immediates (PUSH) and memory (MLOAD). On a
// little-endian target each 8-byte group reads as a word whose byte order is the
// reverse of the wire, so one __bswapdi2 per limb fixes it; bytes[0..7] are the
// most significant, hence limb[3].
inline U256 u256_from_be(const uint8_t bytes[32]) {
    uint64_t w0, w1, w2, w3;
    std::memcpy(&w3, bytes +  0, 8);
    std::memcpy(&w2, bytes +  8, 8);
    std::memcpy(&w1, bytes + 16, 8);
    std::memcpy(&w0, bytes + 24, 8);
    return U256{{__bswapdi2(w0), __bswapdi2(w1), __bswapdi2(w2), __bswapdi2(w3)}};
}

// Store a 256-bit value as 32 big-endian bytes (out[0] is most significant) —
// the inverse of u256_from_be, used by MSTORE / RETURN / LOG / KECCAK input.
inline void u256_to_be(const U256& v, uint8_t out[32]) {
    const uint64_t w3 = __bswapdi2(v.limbs[3]);   // most significant limb -> out[0..7]
    const uint64_t w2 = __bswapdi2(v.limbs[2]);
    const uint64_t w1 = __bswapdi2(v.limbs[1]);
    const uint64_t w0 = __bswapdi2(v.limbs[0]);
    std::memcpy(out +  0, &w3, 8);
    std::memcpy(out +  8, &w2, 8);
    std::memcpy(out + 16, &w1, 8);
    std::memcpy(out + 24, &w0, 8);
}

// Reverse all 32 bytes of a 256-bit word. This converts between the two stack
// representations (see EvmState::stackBE): LE limbs <-> the big-endian wire form
// (the 32 memory/code bytes loaded directly as four little-endian words). It is
// its own inverse. Four __bswapdi2 plus a limb reorder.
inline U256 byteswap256(const U256& x) {
    return U256{{__bswapdi2(x.limbs[3]), __bswapdi2(x.limbs[2]),
                 __bswapdi2(x.limbs[1]), __bswapdi2(x.limbs[0])}};
}

// ----- value helpers (shared by the arithmetic / bitwise opcode handlers) -----
// These interpret the limbs as a little-endian integer, so callers must pass LE
// values — except u256_is_zero, which is the same in either representation.

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

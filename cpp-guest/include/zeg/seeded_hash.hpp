// zeg/seeded_hash.hpp — seeded universal hash for the guest's unordered_maps.
//
// The account/storage/warm-key/transient maps are keyed on values a block
// author chooses freely (addresses, raw SLOAD/SSTORE positions). The old
// hashers truncated the key to 8 bytes, so an author could grind many keys
// into one bucket and turn every lookup into a full chain walk — O(n^2), a
// prover-killer (a stock cold-BALANCE benchmark already collapsed ~22.6k
// accounts into one bucket, ~190x the per-gas cost of a mainnet block).
//
// Fix: a 16-byte random seed (container offset 8, produced fresh per build by
// the input generator) drives a multiply-shift universal hash over ALL key
// bytes: h = c + sum_i a_i * word_i, with secret odd multipliers a_i. The
// author fixes the block before, and independently of, proving and never sees
// the seed, so no key set can force collisions. The seed only picks buckets;
// it never enters the public output (`new_payload_request_root`).
//
// libstdc++ indexes buckets as `hash % prime` (see zisk/runtime.cpp), which
// diffuses all 64 bits, so we return the full 64-bit accumulator unmasked.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace zeg {

// Secret hash parameters, derived once per run from the 16-byte input seed.
// `a` supplies one odd multiplier per 64-bit key word (longest key is a
// 56-byte storage Key = 7 words, so 8 is ample); `c` is the additive constant.
struct HashSeed {
    uint64_t a[8];
    uint64_t c;

    // splitmix64-expand the 16-byte seed into (c, a[0..8]); every a_i forced odd.
    static HashSeed derive(const uint8_t raw[16]) noexcept {
        uint64_t s0, s1;
        std::memcpy(&s0, raw, 8);
        std::memcpy(&s1, raw + 8, 8);
        uint64_t st = s0 ^ (s1 * 0x9E3779B97F4A7C15ull);
        auto next = [&st]() noexcept -> uint64_t {
            st += 0x9E3779B97F4A7C15ull;
            uint64_t z = st;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
            return z ^ (z >> 31);
        };
        HashSeed h{};
        h.c = next();
        for (uint64_t& ai : h.a) {
            ai = next() | 1ull;  // odd multiplier
        }
        return h;
    }
};

// Hash `nbytes` of `key` (nbytes <= 64) as little-endian 64-bit words, the
// final partial word zero-padded. One multiply + add per word; no key byte is
// ignored, so collisions cannot be forced without the seed.
inline uint64_t hash_bytes(const HashSeed& s, const void* key, size_t nbytes) noexcept {
    const uint8_t* p = static_cast<const uint8_t*>(key);
    uint64_t h = s.c;
    size_t full = nbytes >> 3;
    size_t i = 0;
    for (; i < full; ++i) {
        uint64_t word;
        std::memcpy(&word, p + (i << 3), 8);
        h += s.a[i] * word;
    }
    size_t rem = nbytes & 7;
    if (rem) {
        uint64_t word = 0;
        std::memcpy(&word, p + (full << 3), rem);
        h += s.a[i] * word;
    }
    return h;
}

}  // namespace zeg

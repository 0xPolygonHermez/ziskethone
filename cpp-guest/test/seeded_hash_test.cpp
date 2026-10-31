// Host test for zeg/seeded_hash.hpp: the per-run seeded universal hash spreads
// keys over buckets even when an author grinds them to share leading (or
// trailing) bytes. Before it, the maps truncated the key to 8 bytes, so ground
// keys collapsed into one bucket and every lookup walked the whole chain —
// O(n^2), a prover-killer (the contracts-index blow-up in GLAMSTERDAM.md).
//
// We insert adversarial keys into a real std::unordered_map (libstdc++, the
// same `hash % prime` bucket policy as the guest's runtime.cpp) and check the
// longest bucket chain stays near the random balls-in-bins expectation. A
// prefix-truncating hash on the same keys is shown to collapse, so the test
// would catch a regression to one.

#include "zeg/seeded_hash.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

using Key = std::string;  // raw key bytes

struct SeededHasher {
    const zeg::HashSeed* s;
    std::size_t operator()(const Key& k) const noexcept {
        return static_cast<std::size_t>(zeg::hash_bytes(*s, k.data(), k.size()));
    }
};
// The pre-fix mistake: fold only the first 8 bytes.
struct Truncate8Hasher {
    std::size_t operator()(const Key& k) const noexcept {
        std::uint64_t v = 0;
        std::memcpy(&v, k.data(), k.size() < 8 ? k.size() : 8);
        return static_cast<std::size_t>(v);
    }
};

template <class Hasher>
std::size_t max_bucket_chain(const std::vector<Key>& keys, Hasher h) {
    std::unordered_map<Key, int, Hasher> m(0, h);
    for (std::size_t i = 0; i < keys.size(); ++i) m.emplace(keys[i], static_cast<int>(i));
    std::size_t worst = 0;
    for (std::size_t b = 0; b < m.bucket_count(); ++b) worst = std::max(worst, m.bucket_size(b));
    return worst;
}

// N keys of length L that all share `shared` fixed bytes at `front` (prefix) or
// the end (suffix); the rest is a counter, so the keys are distinct.
std::vector<Key> ground_keys(std::size_t N, std::size_t L, std::size_t shared, bool front) {
    std::vector<Key> keys;
    keys.reserve(N);
    for (std::size_t i = 0; i < N; ++i) {
        Key k(L, '\xcc');  // the shared filler
        // place an 8-byte counter where the key is NOT pinned
        const std::size_t at = front ? (L - 8) : 0;
        for (std::size_t b = 0; b < 8 && at + b < L; ++b) k[at + b] = static_cast<char>((i >> (8 * b)) & 0xff);
        (void)shared;
        keys.push_back(std::move(k));
    }
    return keys;
}

void spread(std::size_t L, bool front, const zeg::HashSeed& seed) {
    const std::size_t N = 20000;
    const auto keys = ground_keys(N, L, 8, front);
    const std::size_t seeded = max_bucket_chain(keys, SeededHasher{&seed});
    const std::size_t trunc  = max_bucket_chain(keys, Truncate8Hasher{});
    std::printf("L=%zu %s: seeded worst chain=%zu, truncate8 worst chain=%zu\n",
                L, front ? "shared-prefix" : "shared-suffix", seeded, trunc);
    // Random max load for 20000 keys in ~20000 buckets is ~6-8. Allow 32.
    CHECK(seeded <= 32);
    // The attack keys really are adversarial to a truncating hash: when they
    // share the hashed region (prefix for the 8-byte-prefix case) it collapses.
    if (front) CHECK(trunc >= N / 2);
}

}  // namespace

int main() {
    // A few distinct run seeds; the spread must hold for every one.
    const uint8_t raw_seeds[3][16] = {
        {0x5a,0x45,0x47,0x48,0x45,0x41,0x50,0x47,0x41,0x54,0x45,0x5f,0x53,0x45,0x45,0x44},
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00},
    };
    for (const auto& rs : raw_seeds) {
        const zeg::HashSeed seed = zeg::HashSeed::derive(rs);
        spread(20, true, seed);   // addresses
        spread(32, true, seed);   // code hashes / storage positions
        spread(56, true, seed);   // storage Key (addr+slot)
        spread(32, false, seed);  // shared suffix
    }
    std::printf(g_fail == 0 ? "ALL OK\n" : "%d FAILURES\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}

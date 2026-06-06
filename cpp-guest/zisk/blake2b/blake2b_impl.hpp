// blake2b_impl.hpp — BLAKE2b F compression for the ZisK guest (EIP-152, 0x09),
// per-round mixing via the blake2b_round precompile. Mirrors keccak/sha256 drop-ins.
//
// The ZisK precompile (CSR 0x819) does ONE round of the BLAKE2b mixing (the 8 G
// calls for SIGMA[index]) in place on the 16-word working vector; the F init
// (h‖IV, ⊕t, ⊕~0 if final) and finalize (h ⊕= v ⊕ v[+8]) live here. Dual backend
// (ZEG_ZISK): precompile per round vs a portable G-mixing round for host tests.
// Faithful to zisklib/lib/blake2b.rs and evmone blake2b.cpp. Header-only (zeg::bk)
// so host tests can link evmone's blake2b as the oracle without a symbol clash.

#pragma once

#include <cstdint>

namespace zeg::bk {

inline constexpr uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

#if defined(ZEG_ZISK)

// One BLAKE2b round (SIGMA[index]) via the blake2b_round precompile (0x819).
// Params struct = { index: u64, state: &mut [u64;16], input: &[u64;16] }.
inline void round_mix(uint64_t v[16], const uint64_t m[16], uint64_t index) {
    struct { uint64_t index; uint64_t* state; const uint64_t* input; } p{index, v, m};
    asm volatile("csrs 0x819, %0" : : "r"(&p) : "memory");
}

#else  // ===================== portable software (host) =====================

inline constexpr uint8_t SIGMA[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

inline uint64_t rotr(uint64_t x, unsigned r) { return (x >> r) | (x << (64 - r)); }
inline void g(uint64_t v[16], int a, int b, int c, int d, uint64_t x, uint64_t y) {
    v[a] = v[a] + v[b] + x; v[d] = rotr(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];     v[b] = rotr(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y; v[d] = rotr(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];     v[b] = rotr(v[b] ^ v[c], 63);
}
inline void round_mix(uint64_t v[16], const uint64_t m[16], uint64_t index) {
    const uint8_t* s = SIGMA[index];
    g(v, 0, 4,  8, 12, m[s[0]],  m[s[1]]);
    g(v, 1, 5,  9, 13, m[s[2]],  m[s[3]]);
    g(v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
    g(v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
    g(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
    g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
    g(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
}

#endif  // backend

// EIP-152 BLAKE2b F compression: updates h in place.
inline void compress(uint32_t rounds, uint64_t h[8], const uint64_t m[16],
                     const uint64_t t[2], bool last) {
    alignas(8) uint64_t v[16];
    for (int i = 0; i < 8; ++i) v[i] = h[i];
    for (int i = 0; i < 8; ++i) v[8 + i] = IV[i];
    v[12] ^= t[0];
    v[13] ^= t[1];
    if (last) v[14] ^= ~uint64_t{0};
    for (uint32_t r = 0; r < rounds; ++r) round_mix(v, m, r % 10);
    for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

} // namespace zeg::bk

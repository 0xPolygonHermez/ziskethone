// sha256_impl.hpp — SHA-256 for the ZisK guest, compression via the sha256f
// precompile. Mirrors keccak_zisk.cpp: evmone's padding/block-loop, only the
// Merkle–Damgård compression is delegated to ZisK (CSR 0x805). Dual backend
// (ZEG_ZISK): precompile vs a portable 64-round transform for host tests.
//
// State = the 8 SHA-256 words H0..H7 as uint32_t[8] (native order), passed to the
// precompile as [u64;4]; the 64-byte message block is passed as raw bytes ([u64;8])
// and read big-endian by the precompile. Digest is serialized big-endian.
// Faithful to zisklib/lib/sha256.rs. Header-only (zeg::sh2) so host tests can link
// evmone's sha256 as the oracle without a symbol clash.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace zeg::sh2 {

inline constexpr uint32_t H0[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

#if defined(ZEG_ZISK)

// One SHA-256 compression of a 512-bit block via the sha256f precompile (0x805).
// Params struct = { state: &mut [u64;4], input: &[u64;8] } (SyscallSha256Params).
inline void compress(uint32_t h[8], const uint8_t block[64]) {
    alignas(8) uint64_t in[8];
    std::memcpy(in, block, 64);                       // raw bytes; precompile reads BE
    struct { uint64_t* state; const uint64_t* input; } p{
        reinterpret_cast<uint64_t*>(h), in };
    asm volatile("csrs 0x805, %0" : : "r"(&p) : "memory");
}

#else  // ===================== portable software (host) =====================

inline constexpr uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

inline void compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t)block[i*4] << 24 | (uint32_t)block[i*4+1] << 16 |
               (uint32_t)block[i*4+2] << 8 | (uint32_t)block[i*4+3];
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

#endif  // backend

// Full SHA-256: padding + block loop + big-endian digest. out = 32 bytes.
inline void sha256(uint8_t out[32], const uint8_t* data, size_t size) {
    alignas(8) uint32_t h[8];
    std::memcpy(h, H0, sizeof(h));
    const uint64_t total = (uint64_t)size;

    while (size >= 64) { compress(h, data); data += 64; size -= 64; }

    uint8_t block[64];
    std::memset(block, 0, 64);
    std::memcpy(block, data, size);     // size ∈ [0,63]
    block[size] = 0x80;
    if (size >= 56) {                   // no room for the 64-bit length → extra block
        compress(h, block);
        std::memset(block, 0, 64);
    }
    const uint64_t bits = total * 8;
    for (int i = 0; i < 8; ++i) block[56 + i] = (uint8_t)(bits >> (8 * (7 - i)));  // BE
    compress(h, block);

    for (int i = 0; i < 8; ++i) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

} // namespace zeg::sh2

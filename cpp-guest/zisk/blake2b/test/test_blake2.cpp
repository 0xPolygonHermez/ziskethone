// test_blake2.cpp — host test of our BLAKE2b F compression vs evmone (EVM ref).
//   c++ -std=c++20 -O2 -I.. -I<evmone>/lib/evmone_precompiles test_blake2.cpp \
//       <evmone>/lib/evmone_precompiles/blake2b.cpp -o /tmp/t && /tmp/t
// Differential (our software backend == evmone) over random (rounds,h,m,t,f), plus
// the official EIP-152 "abc" known-answer vector.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include "blake2b.hpp"          // evmone evmone::crypto::blake2b_compress
#include "../blake2b_impl.hpp"  // zeg::bk

static int g_fail = 0;
static void check(bool ok, const char* n){ std::printf("%s %s\n", ok?"ok  ":"FAIL", n); if(!ok)++g_fail; }

static uint64_t s = 0xB1A2E000C0FFEE42ULL;
static uint64_t rnd(){ s = s*6364136223846793005ULL + 1442695040888963407ULL; return s; }

int main() {
    // ---- EIP-152 test vector 4 ("abc", rounds=12, f=1) ----
    {
        uint32_t rounds = 12;
        uint64_t h[8] = {0x6a09e667f2bdc948ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,
                         0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,
                         0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
        uint64_t m[16] = {0x636261ULL,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        uint64_t t[2] = {3,0};
        // known output digest bytes (BLAKE2b("abc")):
        static const uint8_t WANT[64] = {
            0xba,0x80,0xa5,0x3f,0x98,0x1c,0x4d,0x0d,0x6a,0x27,0x97,0xb6,0x9f,0x12,0xf6,0xe9,
            0x4c,0x21,0x2f,0x14,0x68,0x5a,0xc4,0xb7,0x4b,0x12,0xbb,0x6f,0xdb,0xff,0xa2,0xd1,
            0x7d,0x87,0xc5,0x39,0x2a,0xab,0x79,0x2d,0xc2,0x52,0xd5,0xde,0x45,0x33,0xcc,0x95,
            0x18,0xd3,0x8a,0xa8,0xdb,0xf1,0x92,0x5a,0xb9,0x23,0x86,0xed,0xd4,0x00,0x99,0x23};
        uint64_t hm[8]; std::memcpy(hm, h, 64);
        zeg::bk::compress(rounds, hm, m, t, true);
        uint8_t out[64];
        for (int i=0;i<8;++i) for (int j=0;j<8;++j) out[i*8+j] = (uint8_t)(hm[i] >> (8*j));  // LE
        check(std::memcmp(out, WANT, 64) == 0, "EIP-152 vector 4 (\"abc\") KAT");

        uint64_t he[8]; std::memcpy(he, h, 64);
        evmone::crypto::blake2b_compress(rounds, he, m, t, true);
        check(std::memcmp(hm, he, 64) == 0, "vector 4 == evmone");
    }

    // ---- differential vs evmone over random inputs ----
    bool diff = true;
    for (int it = 0; it < 400 && diff; ++it) {
        uint32_t rounds_tbl[] = {0,1,2,7,10,11,12,16,20};
        uint32_t rounds = rounds_tbl[rnd() % 9];
        uint64_t h[8], m[16], t[2];
        for (int i=0;i<8;++i) h[i]=rnd();
        for (int i=0;i<16;++i) m[i]=rnd();
        t[0]=rnd(); t[1]=rnd();
        bool last = (rnd() & 1) != 0;
        uint64_t hm[8]; std::memcpy(hm,h,64);
        uint64_t he[8]; std::memcpy(he,h,64);
        zeg::bk::compress(rounds, hm, m, t, last);
        evmone::crypto::blake2b_compress(rounds, he, m, t, last);
        if (std::memcmp(hm, he, 64) != 0) { diff=false; std::printf("  mismatch rounds=%u last=%d\n", rounds, last); }
    }
    check(diff, "blake2b_compress == evmone (400 random, rounds 0..20, f=0/1)");

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

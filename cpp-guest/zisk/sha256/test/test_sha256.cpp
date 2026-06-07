// test_sha256.cpp — host test of our SHA-256 (software backend) vs evmone (EVM ref).
//   c++ -std=c++20 -O2 -I.. -I<evmone>/lib/evmone_precompiles -I<evmone>/include \
//       test_sha256.cpp <evmone>/lib/evmone_precompiles/sha256.cpp -o /tmp/t && /tmp/t
// Differential over many lengths (padding boundaries at 55/56/63) + known KAT
// digests for "" and "abc".

#include <cstdio>
#include <cstdint>
#include <cstring>
#include "sha256.hpp"        // evmone evmone::crypto::sha256
#include "../sha256_impl.hpp" // zeg::sh2

static int g_fail = 0;
static void check(bool ok, const char* n){ std::printf("%s %s\n", ok?"ok  ":"FAIL", n); if(!ok)++g_fail; }

static bool hexeq(const uint8_t d[32], const char* hex) {
    char buf[65]; for (int i=0;i<32;++i) std::snprintf(buf+i*2,3,"%02x",d[i]);
    return std::strcmp(buf, hex) == 0;
}

int main() {
    // known KAT digests
    { uint8_t d[32]; zeg::sh2::sha256(d, (const uint8_t*)"", 0);
      check(hexeq(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "sha256(\"\") KAT"); }
    { uint8_t d[32]; zeg::sh2::sha256(d, (const uint8_t*)"abc", 3);
      check(hexeq(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256(\"abc\") KAT"); }

    // differential vs evmone over many lengths (incl. padding boundaries)
    static const int LENS[] = {0,1,2,3,31,32,33,55,56,57,63,64,65,119,120,127,128,191,192,1000,4096};
    uint8_t buf[4096];
    uint64_t s = 0xC0FFEE123456789AULL;
    for (size_t i=0;i<sizeof(buf);++i){ s=s*6364136223846793005ULL+1; buf[i]=(uint8_t)(s>>33); }
    bool diff = true;
    for (int L : LENS) {
        uint8_t mine[32]; zeg::sh2::sha256(mine, buf, (size_t)L);
        std::byte ref[32]; evmone::crypto::sha256(ref, (const std::byte*)buf, (size_t)L);
        if (std::memcmp(mine, ref, 32) != 0) { diff=false; std::printf("  mismatch at len %d\n", L); }
    }
    check(diff, "sha256 == evmone over lengths 0..4096 (padding boundaries)");

    // a sweep of every length 0..200 (exhaustive boundary coverage)
    bool sweep = true;
    for (int L=0; L<=200 && sweep; ++L) {
        uint8_t mine[32]; zeg::sh2::sha256(mine, buf, (size_t)L);
        std::byte ref[32]; evmone::crypto::sha256(ref, (const std::byte*)buf, (size_t)L);
        if (std::memcmp(mine, ref, 32) != 0) { sweep=false; std::printf("  sweep mismatch at len %d\n", L); }
    }
    check(sweep, "sha256 == evmone for every length 0..200");

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

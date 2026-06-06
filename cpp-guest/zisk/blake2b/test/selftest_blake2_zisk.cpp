// selftest_blake2_zisk.cpp — on-emulator self-test of the BLAKE2b layer.
//
// Exercises the blake2b_round precompile (CSR 0x819) by running the EIP-152 F
// compression for rounds=1 and rounds=12 (the "abc" vector) and comparing to the
// expected working-state outputs; rounds=0 checks the init/finalize path. Each
// check sets one result bit (slot 0; slot 1 = count). Built as blake2_selftest.elf.
// Run: ziskemu -e blake2_selftest.elf -i <8-byte len=0> -o out.

#include <cstdint>
#include <cstring>
#include "../blake2b_impl.hpp"
#include "zeg/zisk_io.hpp"

using namespace zeg::bk;

static uint32_t g_results = 0;
static int g_bit = 0;
static void rec(bool ok) { if (ok) g_results |= (1u << g_bit); ++g_bit; }

// EIP-152 "abc" inputs (rounds vary): h = IV with h[0]^=0x01010040, m="abc", t=3, f=1.
static const uint64_t H0[8] = {
    0x6a09e667f2bdc948ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};

static bool run_eq(uint32_t rounds, const uint64_t want[8]) {
    uint64_t h[8]; std::memcpy(h, H0, 64);
    uint64_t m[16] = {0x636261ULL,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    uint64_t t[2] = {3,0};
    compress(rounds, h, m, t, true);
    return std::memcmp(h, want, 64) == 0;
}

int main() {
    static const uint64_t R0[8]  = {0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,0x510e527fade682d2ULL,0x9b05688c2b3e6c1fULL,0xe07c265404be4294ULL,0x5be0cd19137e2179ULL};
    static const uint64_t R1[8]  = {0x527d89b20c383ab6ULL,0x182cee3452a89419ULL,0x004c622c4d845f1bULL,0xfbd2493470e97726ULL,0xf5cd3b33a8b351a5ULL,0x2339d59389e0f7f2ULL,0x4e038cc6fc643ddeULL,0x21a4d7fe93927b71ULL};
    static const uint64_t R12[8] = {0x0d4d1c983fa580baULL,0xe9f6129fb697276aULL,0xb7c45a68142f214cULL,0xd1a2ffdb6fbb124bULL,0x2d79ab2a39c5877dULL,0x95cc3345ded552c2ULL,0x5a92f1dba88ad318ULL,0x239900d4ed8623b9ULL};

    rec(run_eq(0,  R0));    // bit0  init/finalize (no precompile)
    rec(run_eq(1,  R1));    // bit1  one precompile round (0x819)
    rec(run_eq(12, R12));   // bit2  EIP-152 "abc" vector (12 precompile rounds)

    zeg::zisk::set_output_u32(0, g_results);
    zeg::zisk::set_output_u32(1, (uint32_t)g_bit);
    return 0;
}

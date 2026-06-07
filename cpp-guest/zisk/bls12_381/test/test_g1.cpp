// test_g1.cpp — host unit test for BLS12-381 G1 (software backend).
//   c++ -std=c++20 -O2 -I.. test_g1.cpp -o /tmp/test_g1 && /tmp/test_g1
// Strong checks: decompress(compressed generator)==G, on-curve, subgroup, and
// r·G == O (the group order annihilates the generator).

#include <cstdio>
#include <cstdint>
#include "../g1.hpp"

using namespace zeg::bls;

static int g_fail = 0;
static void check(bool ok, const char* name) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", name); if (!ok) ++g_fail;
}

// Group order r (Fr modulus), little-endian.
static const uint64_t R[4] = {0xFFFFFFFF00000001ULL,0x53BDA402FFFE5BFEULL,0x3339D80809A1D805ULL,0x73EDA753299D7D48ULL};

// Standard compressed G1 generator (48 bytes, big-endian, flags in byte 0).
static const uint8_t GEN_COMPRESSED[48] = {
    0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
    0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
    0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb};

int main() {
    const G1 G = G1_GENERATOR;
    check(g1_is_on_curve(G), "generator on curve");
    check(g1_is_on_subgroup(G), "generator in subgroup");

    // decompress
    { G1 p; bool inf;
      check(g1_decompress(GEN_COMPRESSED, &p, &inf) && !inf && g1_eq(p, G),
            "decompress(compressed gen) == G");
      uint8_t infbytes[48] = {0}; infbytes[0] = 0xc0;     // compressed + infinity
      G1 q; bool qinf;
      check(g1_decompress(infbytes, &q, &qinf) && qinf && g1_is_identity(q), "decompress(infinity)"); }

    // doubling / addition consistency
    G1 G2 = g1_dbl_raw(G);
    check(g1_is_on_curve(G2), "2G on curve");
    { uint64_t two[4]={2,0,0,0}; check(g1_eq(g1_scalar_mul(G, two), G2), "scalar_mul(G,2)==2G"); }
    G1 acc = G; for (int i = 0; i < 4; ++i) acc = g1_add(acc, G);   // 5G
    { uint64_t five[4]={5,0,0,0}; check(g1_eq(g1_scalar_mul(G, five), acc), "scalar_mul(G,5)==G+G+G+G+G"); }

    // (P+Q)-Q == P
    check(g1_eq(g1_sub(g1_add(G, G2), G2), G), "(G+2G)-2G == G");
    // subgroup closure
    check(g1_is_on_subgroup(G2), "2G in subgroup");

    // r·G == O  — the definitive scalar-mul / order check
    check(g1_is_identity(g1_scalar_mul(G, R)), "r*G == identity");

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

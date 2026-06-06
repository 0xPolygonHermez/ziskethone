// test_g2.cpp — host unit test for BLS12-381 G2 (software backend).
//   c++ -std=c++20 -O2 -I.. test_g2.cpp -o /tmp/test_g2 && /tmp/test_g2

#include <cstdio>
#include <cstdint>
#include "../g2.hpp"

using namespace zeg::bls;

static int g_fail = 0;
static void check(bool ok, const char* name) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", name); if (!ok) ++g_fail;
}
static const uint64_t R[4] = {0xFFFFFFFF00000001ULL,0x53BDA402FFFE5BFEULL,0x3339D80809A1D805ULL,0x73EDA753299D7D48ULL};

int main() {
    const G2 G = G2_GENERATOR;
    check(g2_is_on_curve(G), "generator on curve");

    G2 G2d = g2_dbl(G);
    check(g2_is_on_curve(G2d), "2G on curve");
    { uint64_t two[4]={2,0,0,0}; check(g2_eq(g2_scalar_mul(G, two), G2d), "scalar_mul(G,2)==2G"); }

    G2 acc = G; for (int i = 0; i < 4; ++i) acc = g2_add(acc, G);   // 5G
    { uint64_t five[4]={5,0,0,0}; check(g2_eq(g2_scalar_mul(G, five), acc), "scalar_mul(G,5)==G+..+G"); }

    check(g2_eq(g2_sub(g2_add(G, G2d), G2d), G), "(G+2G)-2G == G");
    check(g2_eq(g2_neg(g2_neg(G)), G), "neg(neg(G))==G");
    check(g2_is_identity(g2_add(G, g2_neg(G))), "G + (-G) == O");

    // r·G == O — definitive scalar-mul / order check over the twist.
    check(g2_is_identity(g2_scalar_mul(G, R)), "r*G == identity");

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

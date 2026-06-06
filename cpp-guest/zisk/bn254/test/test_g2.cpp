// test_g2.cpp — host test of BN254 G2 twist ops (software backend).
//   c++ -std=c++20 -O2 -I.. test_g2.cpp -o /tmp/t && /tmp/t
// Anchored by Python-generated G2 generator multiples (in-subgroup) and one
// on-curve NON-subgroup point. Validates on-curve, the group law, the ψ-based
// subgroup membership (accept subgroup / reject non-subgroup), and [x]·P.

#include <cstdio>
#include <cstdint>
#include "../fp.hpp"
#include "../fp2.hpp"
#include "../g2.hpp"

using namespace zeg::bn;
static int g_fail = 0;
static void check(bool ok, const char* n){ std::printf("%s %s\n", ok?"ok  ":"FAIL", n); if(!ok)++g_fail; }

// Python-generated (gen_g2.py): {x.c0, x.c1, y.c0, y.c1}, each Fp 4 limbs LE.
static const G2 G1g = {{{0x46DEBD5CD992F6EDULL,0x674322D4F75EDADDULL,0x426A00665E5C4479ULL,0x1800DEEF121F1E76ULL},{0x97E485B7AEF312C2ULL,0xF1AA493335A9E712ULL,0x7260BFB731FB5D25ULL,0x198E9393920D483AULL}},{{0x4CE6CC0166FA7DAAULL,0xE3D1E7690C43D37BULL,0x4AAB71808DCB408FULL,0x12C85EA5DB8C6DEBULL},{0x55ACDADCD122975BULL,0xBC4B313370B38EF3ULL,0xEC9E99AD690C3395ULL,0x090689D0585FF075ULL}}};
static const G2 G2g = {{{0x49F8130962B4B3B9ULL,0x9D5CD3CFA9A62AEEULL,0xC36C59277C3E6F14ULL,0x27DC7234FD11D3E8ULL},{0x9957ED8C3928AD79ULL,0x6DB86431C6D83584ULL,0xB60121B83A733370ULL,0x203E205DB4F19B37ULL}},{{0x6E2A6DAD122B5D2EULL,0x44A59B4FE6B1C046ULL,0xA0BC372742C48309ULL,0x04BB53B8977E5F92ULL},{0x98E185F0509DE152ULL,0x3505566B4EDF48D4ULL,0x722B8C153931579DULL,0x195E8AA5B7827463ULL}}};
static const G2 G3g = {{{0x12DEFA0694FBC7F5ULL,0x8D7E478CB09A5E00ULL,0x51E52826E192715EULL,0x06064E784DB10E90ULL},{0xC9824F32FFB66E85ULL,0xBC04156B6878A0A7ULL,0x735191CD5DCFE4EBULL,0x1014772F57BB9742ULL}},{{0x65036D57666C5597ULL,0x69B920D74521E797ULL,0x074B0F9C8D2C68A0ULL,0x058E1D5681B5B9E0ULL},{0x452AEACA147711B2ULL,0xDD9453AC49B55441ULL,0x922FFCC2F38D3323ULL,0x021E2335F3354BB7ULL}}};
static const G2 G7g = {{{0xC390142AAA28B308ULL,0x57A253BA75E32A89ULL,0xED702E01DE1C2F16ULL,0x224BDC5D4327FCF8ULL},{0x593EDEBA46362455ULL,0xBE0FD4516E46EE6DULL,0x6A5D081E84551E63ULL,0x2903BA015A9ABDE2ULL}},{{0x2E21E8054114233FULL,0xD431800ECA28DFD8ULL,0xEECCB372E37D7A7BULL,0x1D92FFF52A265017ULL},{0xBAED1EBE0335E0D8ULL,0x7036BEA1C4E6F7ADULL,0x7AEEAF5FDA464AD1ULL,0x03C8B7CDA6B2DEDBULL}}};
static const G2 NONSUB = {{{0x0000000000000002ULL,0,0,0},{0,0,0,0}},{{0xA8807A52B0FAB5FAULL,0x5959E8398EF0C9BBULL,0x9C47905F002CD608ULL,0x184E49A28B311FE9ULL},{0xE77E74268CACBF14ULL,0x2E52F01F4CFF6CC8ULL,0x238122B710A54D99ULL,0x2B722ED547657A33ULL}}};

int main() {
    check(g2_is_on_curve(G1g) && g2_is_on_curve(G2g) && g2_is_on_curve(G3g) && g2_is_on_curve(G7g), "G2 multiples on curve");
    check(g2_is_on_curve(NONSUB), "nonsub on curve");

    // group law vs anchors
    check(g2_eq(g2_dbl(G1g), G2g), "2·G == dbl(G)");
    check(g2_eq(g2_add(G1g, G2g), G3g), "G + 2G == 3G");
    check(g2_eq(g2_add(G2g, G1g), G3g), "add commutes");
    check(g2_eq(g2_add(G3g, g2_add(G3g, G1g)), G7g), "3G+(3G+G) == 7G");
    check(g2_is_identity(g2_add(G1g, g2_neg(G1g))), "G + (-G) == O");
    check(g2_eq(g2_add(G1g, G2_IDENTITY), G1g), "G + O == G");

    // subgroup membership
    check(g2_is_on_subgroup(G1g), "subgroup: G accepted");
    check(g2_is_on_subgroup(G7g), "subgroup: 7G accepted");
    check(!g2_is_on_subgroup(NONSUB), "subgroup: nonsub rejected");

    // [x]·P stays on curve and in subgroup
    G2 xg = g2_scalar_mul_by_x(G1g);
    check(g2_is_on_curve(xg) && g2_is_on_subgroup(xg), "[x]G on-curve + subgroup");

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

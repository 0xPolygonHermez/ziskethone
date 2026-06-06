// selftest_eip196_zisk.cpp — on-emulator self-test of the BN254 (alt_bn128) layers.
//
// Exercises the precompile + fcall backend (ZEG_ZISK) for ecAdd/ecMul/ecPairing:
// the bn254 curve add/dbl precompiles (0x806/0x807), arith256_mod (0x802),
// complex Fp2 precompiles (0x808/9/A), and the fp_inv/fp2_inv/twist-line/msb
// fcalls. Each check sets one result bit (slot 0; slot 1 = count). Built as
// bn254_selftest.elf. Run: ziskemu -e bn254_selftest.elf -i <8-byte len=0> -o out.

#include <cstdint>
#include "../g1.hpp"
#include "../g2.hpp"
#include "../pairing.hpp"
#include "zeg/zisk_io.hpp"

using namespace zeg::bn;

static uint32_t g_results = 0;
static int g_bit = 0;
static void rec(bool ok) { if (ok) g_results |= (1u << g_bit); ++g_bit; }

// G1 generator (1,2) and G2 generator.
static const G1 G1GEN = {{{1,0,0,0}},{{2,0,0,0}}};
static const G2 G2GEN = {{{0x46DEBD5CD992F6EDULL,0x674322D4F75EDADDULL,0x426A00665E5C4479ULL,0x1800DEEF121F1E76ULL},{0x97E485B7AEF312C2ULL,0xF1AA493335A9E712ULL,0x7260BFB731FB5D25ULL,0x198E9393920D483AULL}},{{0x4CE6CC0166FA7DAAULL,0xE3D1E7690C43D37BULL,0x4AAB71808DCB408FULL,0x12C85EA5DB8C6DEBULL},{0x55ACDADCD122975BULL,0xBC4B313370B38EF3ULL,0xEC9E99AD690C3395ULL,0x090689D0585FF075ULL}}};

int main() {
    // --- G1 add/dbl precompiles (ecAdd) ---
    rec(g1_is_on_curve(G1GEN));                              // bit0
    G1 g2 = g1_add_complete(G1GEN, G1GEN);                  // 2G via dbl precompile
    G1 g3 = g1_add_complete(g2, G1GEN);                     // 3G via add precompile
    rec(g1_is_on_curve(g2) && g1_is_on_curve(g3));         // bit1

    // --- G1 scalar mul (ecMul): [5]G == G+G+G+G+G ---
    {
        uint64_t five[4] = {5,0,0,0};
        G1 a = g1_scalar_mul(G1GEN, five);
        G1 b = g1_add_complete(g1_add_complete(g3, G1GEN), G1GEN);  // 5G
        rec(g1_eq(a, b));                                    // bit2
    }

    // --- G2 (Fp2 complex precompiles + fp2_inv fcall + ψ/frobenius) ---
    rec(g2_is_on_curve(G2GEN));                             // bit3
    rec(g2_is_on_subgroup(G2GEN));                          // bit4

    // --- pairing (miller loop + twist-line fcalls + final exp) ---
    {
        Fp12 e = pairing(G1GEN, G2GEN);
        rec(!fp12_is_one(e));                                // bit5 non-degenerate
        Fp12 en = pairing(g1_neg(G1GEN), G2GEN);
        rec(fp12_is_one(fp12_mul(e, en)));                  // bit6 e(P,Q)·e(-P,Q)==1
    }

    zeg::zisk::set_output_u32(0, g_results);
    zeg::zisk::set_output_u32(1, (uint32_t)g_bit);
    return 0;
}

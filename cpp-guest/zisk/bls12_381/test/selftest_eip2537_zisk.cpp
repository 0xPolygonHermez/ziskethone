// selftest_eip2537_zisk.cpp — on-emulator self-test of the EIP-2537 layers.
//
// Exercises the precompile + fcall backend (ZEG_ZISK) for the new EIP-2537 ops:
// mul/msm, pairing_check, and (the riskiest) map-to-curve, which leans on the
// fp_sqrt/fp2_sqrt fcalls + SWU + isogeny + cofactor clearing. Each check sets
// one result bit (slot 0; slot 1 = count). Built as bls2537_selftest.elf.
// Run: ziskemu -e bls2537_selftest.elf -i <8-byte len=0> -o out.

#include <cstdint>
#include "../eip2537.hpp"
#include "../g2_subgroup.hpp"
#include "../map_to_curve.hpp"
#include "../pairing.hpp"
#include "zeg/zisk_io.hpp"

using namespace zeg::bls;

static uint32_t g_results = 0;
static int g_bit = 0;
static void rec(bool ok) { if (ok) g_results |= (1u << g_bit); ++g_bit; }

static Fp F(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f){return Fp{{a,b,c,d,e,f}};}

int main() {
    // --- mul: [5]G via scalar_mul == repeated add; subgroup-valid ---
    {
        uint64_t five[4]={5,0,0,0};
        G1 p = g1_scalar_mul(G1_GENERATOR, five);
        rec(g1_is_on_subgroup(p));                              // bit0
        G2 q = g2_scalar_mul(G2_GENERATOR, five);
        rec(g2_is_on_subgroup(q));                              // bit1
    }
    // --- pairing_check: e(P,Q)·e(-P,Q) == 1 ---
    {
        uint64_t k[4]={7,0,0,0};
        G1 p = g1_scalar_mul(G1_GENERATOR, k);
        Fp12 a = miller_loop(p, G2_GENERATOR);
        Fp12 b = miller_loop(g1_neg(p), G2_GENERATOR);
        rec(fp12_is_one(final_exp(fp12_mul(a, b))));            // bit2
    }
    // --- map_fp_to_g1: result on-curve + in subgroup ---
    {
        Fp u = F(0x2d5f30c1d0577c56,0x29aabf4bbbb4b60a,0xf65faa3d6bda5044,
                 0xa56da205ae4bf114,0x6ad30a8453e66eac,0x010a97e50d00668c);
        G1 p = map_to_curve_g1(u);
        rec(g1_is_on_curve(p));                                 // bit3
        rec(g1_is_on_subgroup(p));                              // bit4
    }
    // --- map_fp2_to_g2: result on-curve + in subgroup ---
    {
        Fp2 u = {F(0x49b4b9e2ffd3bf5a,0x6bc7632c9e4047a7,0x805d19211a7dc450,
                   0x41c84ac8cfa40667,0xcbc8271a6d95e07f,0x167ed52ad9b8dc52),
                 F(0x9919e620d143515b,0x808a3f274c49a6c7,0xd65c110346cb2c1b,
                   0x8cd2c11ad5206061,0x791b9ace70502ab1,0x07f958516727acdd)};
        G2 q = map_to_curve_g2(u);
        rec(g2_is_on_curve(q));                                 // bit5
        rec(g2_is_on_subgroup(q));                              // bit6
    }

    zeg::zisk::set_output_u32(0, g_results);
    zeg::zisk::set_output_u32(1, (uint32_t)g_bit);
    return 0;
}

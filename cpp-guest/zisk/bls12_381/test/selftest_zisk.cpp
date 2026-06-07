// selftest_zisk.cpp — on-emulator self-test of the BLS12-381 ZisK backend.
//
// The host tests exercise the *software* backend; this ELF exercises the
// *precompile + fcall* backend under ziskemu. Each check sets one bit of a
// result bitmask written to public output slot 0 (slot 1 = number of checks),
// so a 0 bit pinpoints the broken primitive. Built as the bls_selftest.elf
// target (ZEG_ZISK). Run: ziskemu -e bls_selftest.elf -i <8-byte len=0> -o out.

#include <cstdint>
#include "../kzg.hpp"
#include "zeg/zisk_io.hpp"

using namespace zeg::bls;

static uint32_t g_results = 0;
static int g_bit = 0;
static void rec(bool ok) { if (ok) g_results |= (1u << g_bit); ++g_bit; }

static Fp F(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f){return Fp{{a,b,c,d,e,f}};}

int main() {
    static const uint64_t R[4] = {0xFFFFFFFF00000001ULL,0x53BDA402FFFE5BFEULL,0x3339D80809A1D805ULL,0x73EDA753299D7D48ULL};

    (void)R;

    // --- Fp (arith384_mod + fp_inv/fp_sqrt fcalls) ---
    {
        Fp x = F(0x2d5f30c1d0577c56,0x29aabf4bbbb4b60a,0xf65faa3d6bda5044,0xa56da205ae4bf114,0x6ad30a8453e66eac,0x010a97e50d00668c);
        Fp inv = F(0x1d8053f2aed3d017,0x2912c6d8d7c59be0,0xea3af967ab741430,0xdc3cb17c3b332919,0x52a4afd74a0b5b20,0x12be47b0938a6ee1);
        rec(fp_eq(fp_inv(x), inv));                          // bit0
        rec(fp_eq(fp_mul(x, fp_inv(x)), FP_ONE));            // bit1
        Fp sx = F(0xf22cb1516a067d13,0x3e46be206ab02de6,0x93153c30d0917c98,0x597d68ca77b5fa6d,0x44a50733df914e5e,0x0f7377b1bb431d82);
        bool qr; Fp r = fp_sqrt(sx, &qr); rec(qr && fp_eq(fp_sqr(r), sx)); // bit2
    }
    // --- Fp2 (complex precompiles + fp2_inv fcall) ---
    {
        Fp2 a = {F(0x49b4b9e2ffd3bf5a,0x6bc7632c9e4047a7,0x805d19211a7dc450,0x41c84ac8cfa40667,0xcbc8271a6d95e07f,0x167ed52ad9b8dc52),
                 F(0x9919e620d143515b,0x808a3f274c49a6c7,0xd65c110346cb2c1b,0x8cd2c11ad5206061,0x791b9ace70502ab1,0x07f958516727acdd)};
        rec(fp2_eq(fp2_mul(a, fp2_inv(a)), FP2_ONE));        // bit3
        Fp2 b = {F(1,2,3,4,5,6), F(7,8,9,10,11,12)};
        rec(fp2_eq(fp2_mul(a,b), fp2_mul(b,a)));             // bit4 (commutes)
        rec(fp2_eq(fp2_mul(FP2_U,FP2_U), fp2_neg(FP2_ONE))); // bit5 (u²=-1)
    }
    // --- G1 (curve add/dbl precompiles + msb fcall); avoid degenerate r·G ---
    {
        rec(g1_is_on_curve(G1_GENERATOR));                   // bit6
        rec(g1_is_on_subgroup(G1_GENERATOR));                // bit7
        G1 acc = G1_GENERATOR; for (int i=0;i<4;++i) acc = g1_add(acc, G1_GENERATOR); // 5G
        uint64_t five[4]={5,0,0,0};
        rec(g1_eq(g1_scalar_mul(G1_GENERATOR, five), acc));  // bit8 scalar_mul==5·G
    }
    // --- G2 (Fp2 affine + fp2_inv fcall) ---
    {
        rec(g2_is_on_curve(G2_GENERATOR));                   // bit9
        G2 acc = G2_GENERATOR; for (int i=0;i<4;++i) acc = g2_add(acc, G2_GENERATOR);
        uint64_t five[4]={5,0,0,0};
        rec(g2_eq(g2_scalar_mul(G2_GENERATOR, five), acc));  // bit10 scalar_mul==5·G2
    }
    // --- pairing (miller + final exp + twist line fcalls) ---
    {
        Fp12 e = pairing(G1_GENERATOR, G2_GENERATOR);
        rec(!fp12_is_one(e));                                // bit11 non-degenerate
        uint64_t two[4]={2,0,0,0};
        Fp12 e2 = pairing(g1_scalar_mul(G1_GENERATOR,two), G2_GENERATOR);
        rec(fp12_eq(e2, fp12_sqr(e)));                       // bit12 bilinear
    }
    // --- kzg core (constant-poly valid) ---
    {
        uint64_t k[4]={7,0,0,0}; G1 cpt = g1_scalar_mul(G1_GENERATOR, k);
        uint8_t C[48]; g1_compress(cpt, C);
        uint8_t INF[48]={0}; INF[0]=0xc0;
        uint8_t y[32]={0}; y[31]=7; uint8_t z[32]={0}; z[31]=3;
        rec(kzg_verify_core(z, y, C, INF));                  // bit13
    }

    zeg::zisk::set_output_u32(0, g_results);
    zeg::zisk::set_output_u32(1, (uint32_t)g_bit);
    return 0;
}

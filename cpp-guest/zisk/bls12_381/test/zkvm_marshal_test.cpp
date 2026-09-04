// Host-side unit test (x86, not part of the guest build). Build & run:
//   g++ -std=c++20 -O2 cpp-guest/zisk/bls12_381/test/zkvm_marshal_test.cpp -o /tmp/mt && /tmp/mt
// Host test for the BLS repack logic (cpp-guest/zisk/bls12_381/zkvm_marshal.hpp).
// Verifies pad position, coordinate order, round-trip identity, and the msm/pairing
// entry-stride arithmetic — the parts a marshalling bug would corrupt.
#include "../zkvm_marshal.hpp"
#include <cstdio>
#include <cstring>
#include <cstdint>
using namespace zkvm_bls_marshal;

static int fails = 0;
#define CHECK(c) do { if(!(c)){ printf("FAIL: %s (line %d)\n", #c, __LINE__); ++fails; } } while(0)

// Fill a 48-byte "field element" with a recognizable tag so mis-slotting is visible.
static void fp48(uint8_t* p, uint8_t tag) { for (int i=0;i<48;i++) p[i]=(uint8_t)(tag+i); }

int main() {
    // ---- Fp: EF 48 -> guest [16 zero | 48] -> EF 48 (identity + pad) ----
    uint8_t ef_fp[48]; fp48(ef_fp, 0x10);
    uint8_t g_fp[64]; unpack_fp(ef_fp, g_fp);
    for (int i=0;i<16;i++) CHECK(g_fp[i]==0);            // top 16 zero-padded
    CHECK(memcmp(g_fp+16, ef_fp, 48)==0);                // element in low 48
    uint8_t back[48]; pack_fp(g_fp, back); CHECK(memcmp(back, ef_fp, 48)==0);

    // ---- G1: EF [x48|y48] round-trip; verify x,y land in the right halves ----
    uint8_t ef_g1[96]; fp48(ef_g1, 0x20); fp48(ef_g1+48, 0x60);
    uint8_t gx[64], gy[64]; unpack_g1(ef_g1, gx, gy);
    CHECK(memcmp(gx+16, ef_g1, 48)==0);                  // x half
    CHECK(memcmp(gy+16, ef_g1+48, 48)==0);               // y half
    uint8_t r_g1[96]; pack_g1(gx, gy, r_g1); CHECK(memcmp(r_g1, ef_g1, 96)==0);

    // ---- G2: EF [xc0|xc1|yc0|yc1] natural order; verify each component slot ----
    uint8_t ef_g2[192];
    fp48(ef_g2+0,   0x01); fp48(ef_g2+48,  0x02);        // x.c0, x.c1
    fp48(ef_g2+96,  0x03); fp48(ef_g2+144, 0x04);        // y.c0, y.c1
    uint8_t g2x[128], g2y[128]; unpack_g2(ef_g2, g2x, g2y);
    CHECK(memcmp(g2x+16,  ef_g2+0,   48)==0);            // guest x = (c0,c1)
    CHECK(memcmp(g2x+80,  ef_g2+48,  48)==0);
    CHECK(memcmp(g2y+16,  ef_g2+96,  48)==0);            // guest y = (c0,c1)
    CHECK(memcmp(g2y+80,  ef_g2+144, 48)==0);
    uint8_t r_g2[192]; pack_g2(g2x, g2y, r_g2); CHECK(memcmp(r_g2, ef_g2, 192)==0);

    // ---- G1 MSM entry stride: guest 160 (x64,y64,scalar32) -> EF 128 (pt96,scalar32) ----
    // Build a 2-entry guest buffer from two known EF points + scalars, marshal like
    // g1_msm does, and check the EF pair layout byte-for-byte.
    uint8_t guest[2*160];
    uint8_t p0[96]; fp48(p0,0x30); fp48(p0+48,0x70);
    uint8_t p1[96]; fp48(p1,0x31); fp48(p1+48,0x71);
    unpack_g1(p0, guest+0,   guest+64);   for(int i=0;i<32;i++) guest[128+i]=(uint8_t)(0xA0+i);
    unpack_g1(p1, guest+160, guest+224);  for(int i=0;i<32;i++) guest[160+128+i]=(uint8_t)(0xB0+i);
    uint8_t pairs[2*128];
    for (int i=0;i<2;i++){ const uint8_t*e=guest+i*160; uint8_t*d=pairs+i*128; pack_g1(e,e+64,d); memcpy(d+96,e+128,32);}
    CHECK(memcmp(pairs+0,   p0, 96)==0);  CHECK(pairs[96]==0xA0 && pairs[127]==(uint8_t)(0xA0+31));
    CHECK(memcmp(pairs+128, p1, 96)==0);  CHECK(pairs[128+96]==0xB0);

    printf(fails ? "\n%d CHECK(S) FAILED\n" : "ALL MARSHAL CHECKS PASSED\n", fails);
    return fails ? 1 : 0;
}

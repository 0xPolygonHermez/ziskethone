// selftest_backend_zisk.cpp — on-emulator check of the MODEXP backend's ZisK
// path (arith256 precompile 0x801 + fcalls bin_decomp 16 / bigint_div 22), which
// are new/unused. Mirrors test_backend.cpp; writes a result bitmask to output
// slot 0 (slot 1 = #checks). Built as bigint_selftest.elf (ZEG_ZISK).

#include <cstdint>
#include "../backend.hpp"
#include "zeg/zisk_io.hpp"

using namespace zeg::bi;
static uint32_t g_res = 0; static int g_bit = 0;
static void rec(bool ok){ if(ok) g_res |= (1u<<g_bit); ++g_bit; }

int main() {
    { uint64_t a[4]={~0ULL,0,0,0}, b[4]={~0ULL,0,0,0}, c[4]={0,0,0,0}, dl[4], dh[4];
      arith256(a,b,c,dl,dh);
      rec(dl[0]==1 && dl[1]==0xFFFFFFFFFFFFFFFEULL && dl[2]==0 && dl[3]==0 &&
          dh[0]==0&&dh[1]==0&&dh[2]==0&&dh[3]==0); }                        // bit0
    { uint64_t a[4]={7,0,0,0}, b[4]={6,0,0,0}, c[4]={5,0,0,0}, dl[4], dh[4];
      arith256(a,b,c,dl,dh); rec(dl[0]==47&&dl[1]==0&&dh[0]==0); }          // bit1
    { uint64_t a[4]={7,0,0,0}, b[4]={6,0,0,0}, c[4]={5,0,0,0}, m[4]={10,0,0,0}, d[4];
      arith256_mod(a,b,c,m,d); rec(d[0]==7&&d[1]==0&&d[2]==0&&d[3]==0); }    // bit2
    { uint64_t a[1]={11}; uint64_t bits[128]; int n=fcall_bin_decomp(a,1,bits);
      rec(n==4 && bits[0]==1&&bits[1]==0&&bits[2]==1&&bits[3]==1); }         // bit3
    { uint64_t big[2]={0,1}; uint64_t bits[128]; int n=fcall_bin_decomp(big,2,bits);
      rec(n==65 && bits[0]==1 && bits[64]==0); }                            // bit4
    { uint64_t a[1]={100}, b[1]={7}, q[64], r[64]; int lq,lr;
      fcall_bigint_div(a,1,b,1,q,&lq,r,&lr);  // lengths padded to ×4
      rec(lq==4&&q[0]==14&&q[1]==0&&lr==4&&r[0]==2&&r[1]==0); }              // bit5
    { uint64_t a[3]={0,0,1}, b[2]={1,1}, q[64], r[64]; int lq,lr;
      fcall_bigint_div(a,3,b,2,q,&lq,r,&lr);
      rec(q[0]==0xFFFFFFFFFFFFFFFFULL && q[1]==0 && lq==4 && r[0]==1 && r[1]==0 && lr==4); } // bit6

    zeg::zisk::set_output_u32(0, g_res);
    zeg::zisk::set_output_u32(1, (uint32_t)g_bit);
    return 0;
}

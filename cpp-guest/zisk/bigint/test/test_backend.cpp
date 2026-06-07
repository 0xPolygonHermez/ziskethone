// test_backend.cpp — host KAT for the MODEXP backend primitives (software path).
//   c++ -std=c++20 -O2 -I.. test_backend.cpp -o /tmp/test_bbk && /tmp/test_bbk

#include <cstdio>
#include <cstdint>
#include "../backend.hpp"

using namespace zeg::bi;

static int g_fail = 0;
static void check(bool ok, const char* n){ std::printf("%s %s\n", ok?"ok  ":"FAIL", n); if(!ok)++g_fail; }

int main() {
    // arith256: (2^64-1)^2 = 0xFFFFFFFFFFFFFFFE_0000000000000001
    {
        uint64_t a[4]={~0ULL,0,0,0}, b[4]={~0ULL,0,0,0}, c[4]={0,0,0,0}, dl[4], dh[4];
        arith256(a,b,c,dl,dh);
        check(dl[0]==1 && dl[1]==0xFFFFFFFFFFFFFFFEULL && dl[2]==0 && dl[3]==0, "arith256 (2^64-1)^2 low");
        check(dh[0]==0&&dh[1]==0&&dh[2]==0&&dh[3]==0, "arith256 high=0");
    }
    // arith256 with carry into high: 2^192 * 2^64 = 2^256 -> dh[0]=1
    {
        uint64_t a[4]={0,0,0,1}, b[4]={1,0,0,0}, c[4]={0,0,0,0}, dl[4], dh[4]; // a=2^192,b=1 -> dl[3]=1
        arith256(a,b,c,dl,dh); check(dl[3]==1&&dh[0]==0, "arith256 2^192*1");
        uint64_t a2[4]={0,0,0,1}, b2[4]={0,1,0,0}; // 2^192 * 2^64 = 2^256 -> dh[0]=1
        arith256(a2,b2,c,dl,dh); check(dh[0]==1 && dl[0]==0&&dl[1]==0&&dl[2]==0&&dl[3]==0, "arith256 2^256 -> dh");
    }
    // arith256 + c
    {
        uint64_t a[4]={7,0,0,0}, b[4]={6,0,0,0}, c[4]={5,0,0,0}, dl[4], dh[4];
        arith256(a,b,c,dl,dh); check(dl[0]==47&&dl[1]==0&&dh[0]==0, "arith256 7*6+5=47");
    }
    // arith256_mod: (7*6+5) mod 10 = 7
    {
        uint64_t a[4]={7,0,0,0}, b[4]={6,0,0,0}, c[4]={5,0,0,0}, m[4]={10,0,0,0}, d[4];
        arith256_mod(a,b,c,m,d); check(d[0]==7&&d[1]==0&&d[2]==0&&d[3]==0, "arith256_mod 47 mod 10 = 7");
    }
    // bin_decomp: 11 = 0b1011 -> [1,0,1,1]
    {
        uint64_t a[1]={11}; uint64_t bits[128]; int n=fcall_bin_decomp(a,1,bits);
        check(n==4 && bits[0]==1&&bits[1]==0&&bits[2]==1&&bits[3]==1, "bin_decomp 11");
        uint64_t z[1]={0}; check(fcall_bin_decomp(z,1,bits)==0, "bin_decomp 0 -> 0 bits");
        uint64_t big[2]={0,1}; // 2^64 -> 65 bits, MSB then 64 zeros
        n=fcall_bin_decomp(big,2,bits); check(n==65 && bits[0]==1 && bits[64]==0, "bin_decomp 2^64");
    }
    // bigint_div: 100 / 7 = 14 r 2
    {
        uint64_t a[1]={100}, b[1]={7}, q[64], r[64]; int lq,lr;
        fcall_bigint_div(a,1,b,1,q,&lq,r,&lr);  // lengths padded to ×4 (U256 words)
        check(lq==4&&q[0]==14&&q[1]==0&&q[2]==0&&q[3]==0&&lr==4&&r[0]==2&&r[1]==0, "bigint_div 100/7=14 r2");
        // multi-limb: (2^128) / (2^64+1)
        uint64_t a2[3]={0,0,1}, b2[2]={1,1}; // a=2^128, b=2^64+1
        fcall_bigint_div(a2,3,b2,2,q,&lq,r,&lr);
        // 2^128 = (2^64+1)*q + r ; q = 2^64 - 1 = 0xFFFF..FF, r = 1
        check(q[0]==0xFFFFFFFFFFFFFFFFULL && q[1]==0 && lq==4 && r[0]==1 && r[1]==0 && lr==4, "bigint_div 2^128/(2^64+1)");
    }
    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

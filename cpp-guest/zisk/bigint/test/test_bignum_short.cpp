// test_bignum_short.cpp — host test for the MODEXP short-path arithmetic.
//   c++ -std=c++20 -O2 -I.. test_bignum_short.cpp -o /tmp/t && /tmp/t
// Cross-checks mul/square+reduce against the independent arith256_mod, and
// rem_short against the independent 512-mod-256 reduction.

#include <cstdio>
#include <cstdint>
#include "../bignum.hpp"

using namespace zeg::bi;
static int g_fail = 0;
static void check(bool ok, const char* n){ std::printf("%s %s\n", ok?"ok  ":"FAIL", n); if(!ok)++g_fail; }

// crude LCG to generate pseudo-random 256-bit words
static uint64_t s = 0x123456789abcdef0ULL;
static uint64_t rnd(){ s = s*6364136223846793005ULL + 1442695040888963407ULL; return s; }
static void rword(uint64_t w[4]){ for(int i=0;i<4;++i) w[i]=rnd(); }

int main() {
    for (int iter = 0; iter < 2000; ++iter) {
        uint64_t a[4], b[4], m[4];
        rword(a); rword(b); rword(m);
        if (is_zero4(m)) m[0]=1;
        // mul_and_reduce_short(a,b,m) == arith256_mod(a,b,0,m)
        uint64_t r1[4], r2[4], zero[4]={0,0,0,0};
        mul_and_reduce_short(a,b,m,r1);
        arith256_mod(a,b,zero,m,r2);
        if (!eq4(r1,r2)) { check(false,"mul_and_reduce_short == arith256_mod"); break; }
        // square_and_reduce_short(a,m) == arith256_mod(a,a,0,m)
        square_and_reduce_short(a,m,r1);
        arith256_mod(a,a,zero,m,r2);
        if (!eq4(r1,r2)) { check(false,"square_and_reduce_short == arith256_mod"); break; }
        // rem_short of a 2-word N mod m == mod512(N,m)
        uint64_t N[8]; rword(N); rword(N+4);
        if (is_zero4(N+4)) N[4]=1;          // ensure 2-word (no leading zero word)
        uint64_t rr[4], ref[4];
        rem_short(N, 2, m, rr);
        detail::mod512(N, m, ref);
        if (!eq4(rr,ref)) { check(false,"rem_short(2-word) == mod512"); break; }
    }
    if (g_fail==0) check(true, "2000 random short-path cases (mul/sq+reduce, rem) vs references");

    // edge cases
    { uint64_t a[4]={5,0,0,0}, m[4]={5,0,0,0}, r[4]; uint64_t one[4]={1,0,0,0};
      mul_and_reduce_short(a,one,m,r); check(is_zero4(r), "5*1 mod 5 == 0"); }
    { uint64_t a[4]={7,0,0,0}, b[4]={1,0,0,0}, m[4]={100,0,0,0}, r[4];
      mul_and_reduce_short(a,b,m,r); check(r[0]==7&&r[1]==0, "7*1 mod 100 == 7"); }

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

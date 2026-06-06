// test_fp.cpp — host test of the BN254 field tower (software backend).
//   c++ -std=c++20 -O2 -I.. test_fp.cpp -o /tmp/t && /tmp/t
// Validates Fp/Fp2/Fp6/Fp12 via algebraic identities + Python-computed anchors.
// The Frobenius operators are checked exactly via frob1ⁿ == frob_n and frob1¹²==id,
// which pins the γ constants. The full pairing KAT vs evmone follows in N4.

#include <cstdio>
#include <cstdint>
#include "../fp.hpp"
#include "../fp2.hpp"
#include "../fp6.hpp"
#include "../fp12.hpp"

using namespace zeg::bn;
static int g_fail = 0;
static void check(bool ok, const char* n){ std::printf("%s %s\n", ok?"ok  ":"FAIL", n); if(!ok)++g_fail; }

static uint64_t s = 0x2545F4914F6CDD1DULL;
static uint64_t rnd(){ s = s*6364136223846793005ULL + 1442695040888963407ULL; return s; }
static Fp rfp(){ Fp r{{rnd(),rnd(),rnd(),rnd()}}; r.c[3] &= 0x0FFFFFFFFFFFFFFFULL; return r; }  // < p
static Fp2 rfp2(){ return { rfp(), rfp() }; }
static Fp6 rfp6(){ return { rfp2(), rfp2(), rfp2() }; }
static Fp12 rfp12(){ return { rfp6(), rfp6() }; }

int main() {
    // ---- Fp anchors (Python: x*y, 1/x mod p) ----
    Fp x{{0x99AABBCCDDEEFF00ULL,0x1122334455667788ULL,0xFEDCBA9876543210ULL,0x123456789ABCDEF0ULL}};
    Fp y{{0xFEDCBA9876543210ULL,0xABCDEF0123456789ULL,0x0706050403020100ULL,0x0F0E0D0C0B0A0908ULL}};
    Fp xy{{0x4709F78B112EED28ULL,0x509F774936560EF6ULL,0x8E57D46F51311479ULL,0x1590FB1F10183C2CULL}};
    Fp xinv{{0x458368DAD211A1CBULL,0xA0EDA301DCF05DF7ULL,0x815FBF35C5A1C1ACULL,0x1DF00ED6B6D5088CULL}};
    check(fp_eq(fp_mul(x,y), xy), "fp_mul anchor");
    check(fp_eq(fp_inv(x), xinv), "fp_inv anchor");
    check(fp_eq(fp_mul(x, fp_inv(x)), FP_ONE), "fp x·x⁻¹==1");
    check(fp_eq(fp_add(x, fp_neg(x)), FP_ZERO), "fp x+(-x)==0");

    // ---- Fp2 ----
    { Fp2 a=rfp2(), b=rfp2(), c=rfp2();
      check(fp2_eq(fp2_mul(a, fp2_inv(a)), FP2_ONE), "fp2 a·a⁻¹==1");
      check(fp2_eq(fp2_mul(a,b), fp2_mul(b,a)), "fp2 commutes");
      check(fp2_eq(fp2_sqr(a), fp2_mul(a,a)), "fp2 sqr");
      check(fp2_eq(fp2_mul(fp2_add(a,b),c), fp2_add(fp2_mul(a,c),fp2_mul(b,c))), "fp2 distributes");
      check(fp2_eq(fp2_mul(FP2_U,FP2_U), fp2_neg(FP2_ONE)), "fp2 u²==-1"); }

    // ---- Fp6 ----
    { Fp6 a=rfp6(), b=rfp6(), c=rfp6();
      check(fp6_eq(fp6_mul(a, fp6_inv(a)), FP6_ONE), "fp6 a·a⁻¹==1");
      check(fp6_eq(fp6_sqr(a), fp6_mul(a,a)), "fp6 sqr");
      check(fp6_eq(fp6_mul(fp6_add(a,b),c), fp6_add(fp6_mul(a,c),fp6_mul(b,c))), "fp6 distributes"); }

    // ---- Fp12 ----
    { Fp12 a=rfp12(), b=rfp12(), c=rfp12();
      check(fp12_eq(fp12_mul(a, fp12_inv(a)), FP12_ONE), "fp12 a·a⁻¹==1");
      check(fp12_eq(fp12_sqr(a), fp12_mul(a,a)), "fp12 sqr");
      check(fp12_eq(fp12_mul(fp12_add(a,b),c), fp12_add(fp12_mul(a,c),fp12_mul(b,c))), "fp12 distributes"); }

    // ---- Frobenius: frob1ⁿ == frob_n, frob1¹² == id, homomorphism ----
    { Fp12 a=rfp12(), b=rfp12();
      Fp12 f1 = fp12_frobenius1(a);
      check(fp12_eq(fp12_frobenius1(f1), fp12_frobenius2(a)), "frob1∘frob1 == frob2");
      check(fp12_eq(fp12_frobenius1(fp12_frobenius2(a)), fp12_frobenius3(a)), "frob1∘frob2 == frob3");
      check(fp12_eq(fp12_frobenius1(fp12_mul(a,b)), fp12_mul(fp12_frobenius1(a),fp12_frobenius1(b))), "frob1 homomorphism");
      Fp12 t = a; for (int i=0;i<12;++i) t = fp12_frobenius1(t);
      check(fp12_eq(t, a), "frob1¹² == identity"); }

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

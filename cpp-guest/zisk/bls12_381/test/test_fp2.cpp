// test_fp2.cpp — host unit test for the BLS12-381 Fp2 layer (software backend).
//   c++ -std=c++20 -O2 -I.. test_fp2.cpp -o /tmp/test_fp2 && /tmp/test_fp2
// KAT vectors lifted from zisklib fcalls_impl/bls12_381 Rust tests.

#include <cstdio>
#include <cstdint>
#include "../fp2.hpp"

using namespace zeg::bls;

static int g_fail = 0;
static void check(bool ok, const char* name) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", name); if (!ok) ++g_fail;
}
static Fp2 F2(const uint64_t v[12]) { Fp2 r; for (int i=0;i<6;++i){r.c0.c[i]=v[i]; r.c1.c[i]=v[6+i];} return r; }

int main() {
    // --- inverse KAT (fcalls_impl/bls12_381/fp2_inv.rs test_inv) ---
    {
        const uint64_t xv[12] = {
            0x49b4b9e2ffd3bf5a,0x6bc7632c9e4047a7,0x805d19211a7dc450,0x41c84ac8cfa40667,0xcbc8271a6d95e07f,0x167ed52ad9b8dc52,
            0x9919e620d143515b,0x808a3f274c49a6c7,0xd65c110346cb2c1b,0x8cd2c11ad5206061,0x791b9ace70502ab1,0x07f958516727acdd};
        const uint64_t iv[12] = {
            0x55aa5b187f77e83e,0xff523f3ab3ac46a6,0xf686d520afbeb578,0xb1664497d371019b,0xcfef6ce72c61e835,0x1474b2da727c6dfe,
            0x5730d5d619884057,0xd42b3decc96db687,0x8abb9a0eed22a8a3,0xd2f92c46b24958f7,0x8ab323bd7384ca05,0x1859d94eddac5b45};
        Fp2 x = F2(xv), want = F2(iv);
        check(fp2_eq(fp2_inv(x), want), "fp2_inv KAT");
        check(fp2_eq(fp2_mul(x, fp2_inv(x)), FP2_ONE), "a * inv(a) == 1");
        check(fp2_eq(fp2_inv(FP2_ONE), FP2_ONE), "inv(1) == 1");
    }
    // --- sqrt KAT QR (fcalls_impl/bls12_381/fp2_sqrt.rs test_sqrt) ---
    {
        const uint64_t xv[12] = {
            0x10486089be1876e9,0xcf0c3012bf0c13ef,0x51621421d2c37a8d,0xd52db71259449a47,0x370fd7a0a4be29da,0x0c3d4fd75c076215,
            0x3e6ff1a3151b0959,0x9f0b2a8dea2c9f82,0xb83d47ccb71501e2,0xa8c917818d857f05,0xc48150d1cd95e0c6,0x112ca78116187cc8};
        Fp2 x = F2(xv); bool qr; Fp2 r = fp2_sqrt(x, &qr);
        check(qr, "fp2_sqrt QR flag");
        check(fp2_eq(fp2_sqr(r), x), "fp2_sqrt: r^2 == x");
    }
    // --- sqrt KAT non-QR (test_no_sqrt) ---
    {
        const uint64_t xv[12] = {
            0x5531f66e0c366bf8,0x35f8f154ff2974e6,0xaa81eb7e92ae7b5e,0x8a521c9ff4654bc0,0xa224f0e84356bba8,0x0ffbbc4bdd5425cb,
            0xf16972261c97a569,0xbf071b2a52d05a68,0xbaa99b2bc5260f74,0xedbd0c20e26eb5e5,0x6f3229e291d1d67a,0x119353ab08784f06};
        Fp2 x = F2(xv); bool qr; Fp2 r = fp2_sqrt(x, &qr);
        check(!qr, "fp2_sqrt non-QR flag");
        check(fp2_eq(fp2_sqr(r), fp2_mul(x, FP2_NQR)), "fp2_sqrt: r^2 == x*NQR");
    }
    // --- identities ---
    {
        const uint64_t av[12] = {
            0x49b4b9e2ffd3bf5a,0x6bc7632c9e4047a7,0x805d19211a7dc450,0x41c84ac8cfa40667,0xcbc8271a6d95e07f,0x167ed52ad9b8dc52,
            0x9919e620d143515b,0x808a3f274c49a6c7,0xd65c110346cb2c1b,0x8cd2c11ad5206061,0x791b9ace70502ab1,0x07f958516727acdd};
        const uint64_t bv[12] = {
            0x10486089be1876e9,0xcf0c3012bf0c13ef,0x51621421d2c37a8d,0xd52db71259449a47,0x370fd7a0a4be29da,0x0c3d4fd75c076215,
            0x3e6ff1a3151b0959,0x9f0b2a8dea2c9f82,0xb83d47ccb71501e2,0xa8c917818d857f05,0xc48150d1cd95e0c6,0x112ca78116187cc8};
        Fp2 a = F2(av), b = F2(bv);
        check(fp2_eq(fp2_mul(a, b), fp2_mul(b, a)), "mul commutes");
        check(fp2_eq(fp2_sub(fp2_add(a, b), b), a), "(a+b)-b == a");
        check(fp2_eq(fp2_conjugate(fp2_conjugate(a)), a), "conj(conj(a)) == a");
        check(fp2_eq(fp2_sqr(a), fp2_mul(a, a)), "sqr == mul");
        check(fp2_eq(fp2_dbl(a), fp2_add(a, a)), "dbl == add");
        check(fp2_eq(fp2_add(a, fp2_neg(a)), FP2_ZERO), "a + (-a) == 0");
        check(fp2_eq(fp2_mul_by_nonresidue(a), fp2_mul(a, FP2_NQR)), "mul_by_nonresidue == *(1+u)");
        // u² == -1
        check(fp2_eq(fp2_mul(FP2_U, FP2_U), fp2_neg(FP2_ONE)), "u^2 == -1");
    }

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

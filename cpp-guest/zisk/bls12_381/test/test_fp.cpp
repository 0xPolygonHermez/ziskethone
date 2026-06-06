// test_fp.cpp — host unit test for the BLS12-381 Fp layer (software backend).
//
// Builds WITHOUT ZEG_ZISK, so fp.hpp uses its portable software path. Checks the
// known-answer vectors lifted from zisklib's fcalls_impl/bls12_381 Rust tests,
// plus algebraic identities. Run:
//   c++ -std=c++20 -O2 -I.. test_fp.cpp -o /tmp/test_fp && /tmp/test_fp

#include <cstdio>
#include <cstdint>
#include "../fp.hpp"

using namespace zeg::bls;

static int g_fail = 0;
static void check(bool ok, const char* name) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) ++g_fail;
}
static Fp F(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
    return Fp{{a, b, c, d, e, f}};
}

int main() {
    // --- inverse KAT (fcalls_impl/bls12_381/fp_inv.rs test_inv) ---
    {
        Fp x = F(0x2d5f30c1d0577c56, 0x29aabf4bbbb4b60a, 0xf65faa3d6bda5044,
                 0xa56da205ae4bf114, 0x6ad30a8453e66eac, 0x010a97e50d00668c);
        Fp want = F(0x1d8053f2aed3d017, 0x2912c6d8d7c59be0, 0xea3af967ab741430,
                    0xdc3cb17c3b332919, 0x52a4afd74a0b5b20, 0x12be47b0938a6ee1);
        check(fp_eq(fp_inv(x), want), "fp_inv KAT");
        check(fp_eq(fp_mul(x, fp_inv(x)), FP_ONE), "x * inv(x) == 1");
        check(fp_eq(fp_inv(FP_ONE), FP_ONE), "inv(1) == 1");
        check(fp_is_zero(fp_inv(FP_ZERO)), "inv(0) == 0");
    }
    // --- sqrt KAT, QR case (fcalls_impl/bls12_381/fp_sqrt.rs test_sqrt) ---
    {
        Fp x = F(0xf22cb1516a067d13, 0x3e46be206ab02de6, 0x93153c30d0917c98,
                 0x597d68ca77b5fa6d, 0x44a50733df914e5e, 0x0f7377b1bb431d82);
        Fp want = F(0x516e9b68ec7e4040, 0x4b1f0de82104d372, 0x7e742e30000909d7,
                    0x44051766a1553492, 0xe7043ea4bffc292f, 0x03efcb69d6bf0ce0);
        bool qr; Fp r = fp_sqrt(x, &qr);
        check(qr && fp_eq(r, want), "fp_sqrt KAT (QR)");
        check(fp_eq(fp_sqr(r), x), "sqrt(x)^2 == x");
    }
    // --- sqrt KAT, non-QR case (fcalls_impl/bls12_381/fp_sqrt.rs test_no_sqrt) ---
    {
        Fp x = F(0x361799ccd540a764, 0xf606e6b453a13bd8, 0x8880bd6a4b0b963a,
                 0x8c9a8b3ba67f6d02, 0x922d30923791c733, 0x1975e3ccd03944ca);
        Fp want = F(0x5514d9e1a2faebf1, 0x391ed94dec028013, 0x5a8c79b17991fded,
                    0x56207337f5f736d0, 0x0c6f1181533cc4b6, 0x0b1d40edb0c1fec0);
        bool qr; Fp r = fp_sqrt(x, &qr);
        check(!qr && fp_eq(r, want), "fp_sqrt KAT (non-QR)");
        Fp xn = fp_mul(x, FP_NQR);
        check(fp_eq(fp_sqr(r), xn), "sqrt(x*NQR)^2 == x*NQR");
    }
    // --- algebraic identities ---
    {
        Fp x = F(0x2d5f30c1d0577c56, 0x29aabf4bbbb4b60a, 0xf65faa3d6bda5044,
                 0xa56da205ae4bf114, 0x6ad30a8453e66eac, 0x010a97e50d00668c);
        Fp y = F(0xf22cb1516a067d13, 0x3e46be206ab02de6, 0x93153c30d0917c98,
                 0x597d68ca77b5fa6d, 0x44a50733df914e5e, 0x0f7377b1bb431d82);
        check(fp_eq(fp_sub(fp_add(x, y), y), x), "(x+y)-y == x");
        check(fp_eq(fp_add(x, fp_neg(x)), FP_ZERO), "x + (-x) == 0");
        check(fp_eq(fp_dbl(x), fp_add(x, x)), "dbl(x) == x+x");
        check(fp_eq(fp_sqr(x), fp_mul(x, x)), "sqr(x) == x*x");
        check(fp_eq(fp_sub(x, x), FP_ZERO), "x-x == 0");
        // p ≡ 3 (mod 4): p[0] & 3 == 3
        check((FP_P.c[0] & 3) == 3, "p == 3 (mod 4)");
        // round-trip bytes
        uint8_t b[48]; fp_to_bytes_be(x, b);
        check(fp_eq(fp_from_bytes_be(b), x), "bytes_be round-trip");
    }

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

// test_fp12.cpp — host unit test for the Fp6/Fp12 tower (software backend).
//   c++ -std=c++20 -O2 -I.. test_fp12.cpp -o /tmp/test_fp12 && /tmp/test_fp12
// No public KAT vectors for the tower in zisklib, so we use strong algebraic
// identities — in particular ones that pin the Frobenius constants (p-power map
// is multiplicative, has order 12, and frob2 == frob1∘frob1).

#include <cstdio>
#include <cstdint>
#include "../fp12.hpp"

using namespace zeg::bls;

static int g_fail = 0;
static void check(bool ok, const char* name) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", name); if (!ok) ++g_fail;
}

// Two valid base field elements (from the Fp KAT) to seed pseudo-random values.
static const Fp V0 = {{0x2d5f30c1d0577c56,0x29aabf4bbbb4b60a,0xf65faa3d6bda5044,0xa56da205ae4bf114,0x6ad30a8453e66eac,0x010a97e50d00668c}};
static const Fp V1 = {{0xf22cb1516a067d13,0x3e46be206ab02de6,0x93153c30d0917c98,0x597d68ca77b5fa6d,0x44a50733df914e5e,0x0f7377b1bb431d82}};
static Fp gen(int i) { Fp s{{(uint64_t)(i+1),0,0,0,0,0}}; return fp_add(fp_mul(V0, s), V1); }  // valid (<p)

static Fp12 mk(int base) {
    Fp12 a; Fp* s = reinterpret_cast<Fp*>(&a);          // 24 contiguous Fp
    for (int i = 0; i < 24; ++i) s[i] = gen(base + i);
    return a;
}

int main() {
    Fp12 a = mk(0), b = mk(5), c = mk(11);

    // ----- Fp6 -----
    Fp6 p = a.c0, q = b.c0, r = c.c0;
    check(fp6_eq(fp6_mul(p, fp6_inv(p)), FP6_ONE), "fp6: p*inv(p)==1");
    check(fp6_eq(fp6_mul(p, q), fp6_mul(q, p)), "fp6: mul commutes");
    check(fp6_eq(fp6_mul(fp6_mul(p, q), r), fp6_mul(p, fp6_mul(q, r))), "fp6: mul assoc");
    check(fp6_eq(fp6_sqr(p), fp6_mul(p, p)), "fp6: sqr==mul");
    check(fp6_eq(fp6_mul(p, fp6_add(q, r)), fp6_add(fp6_mul(p,q), fp6_mul(p,r))), "fp6: distributive");
    {
        Fp6 V = {FP2_ZERO, FP2_ONE, FP2_ZERO};           // the element v
        check(fp6_eq(fp6_mul_by_v(p), fp6_mul(p, V)), "fp6: mul_by_v == *v");
        Fp2 b2 = q.c1, b3 = q.c2, b1 = q.c0;
        check(fp6_eq(fp6_sparse_mulb(p, b2, b3), fp6_mul(p, Fp6{FP2_ZERO, b2, b3})), "fp6: sparse_mulb");
        check(fp6_eq(fp6_sparse_mulc(p, b1, b3), fp6_mul(p, Fp6{b1, FP2_ZERO, b3})), "fp6: sparse_mulc");
        check(fp6_eq(fp6_sparse_mula(p, b2), fp6_mul(p, Fp6{FP2_ZERO, b2, FP2_ZERO})), "fp6: sparse_mula");
    }

    // ----- Fp12 -----
    check(fp12_eq(fp12_mul(a, fp12_inv(a)), FP12_ONE), "fp12: a*inv(a)==1");
    check(fp12_eq(fp12_mul(a, b), fp12_mul(b, a)), "fp12: mul commutes");
    check(fp12_eq(fp12_mul(fp12_mul(a,b),c), fp12_mul(a,fp12_mul(b,c))), "fp12: mul assoc");
    check(fp12_eq(fp12_sqr(a), fp12_mul(a, a)), "fp12: sqr==mul");
    check(fp12_eq(fp12_conjugate(fp12_conjugate(a)), a), "fp12: conj(conj(a))==a");
    {
        Fp2 b22 = b.c0.c1, b23 = b.c0.c2;
        Fp12 B; B.c0 = FP6_ONE; B.c1 = Fp6{FP2_ZERO, b22, b23};   // 1 + (b22 v + b23 v²) w
        check(fp12_eq(fp12_sparse_mul(a, b22, b23), fp12_mul(a, B)), "fp12: sparse_mul == full mul");
    }
    // Frobenius: pins the gamma constants.
    check(fp12_eq(fp12_frobenius1(FP12_ONE), FP12_ONE), "frob1(1)==1");
    check(fp12_eq(fp12_frobenius1(fp12_mul(a,b)), fp12_mul(fp12_frobenius1(a), fp12_frobenius1(b))),
          "frob1 multiplicative");
    check(fp12_eq(fp12_frobenius2(a), fp12_frobenius1(fp12_frobenius1(a))), "frob2 == frob1^2");
    {
        Fp12 t = a;
        for (int i = 0; i < 12; ++i) t = fp12_frobenius1(t);
        check(fp12_eq(t, a), "frob1^12 == identity");
    }

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

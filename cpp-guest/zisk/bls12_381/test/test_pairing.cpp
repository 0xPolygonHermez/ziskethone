// test_pairing.cpp — host unit test for the BLS12-381 pairing (software backend).
//   c++ -std=c++20 -O2 -I.. test_pairing.cpp -o /tmp/test_pairing && /tmp/test_pairing
// Checks the dbl-line-coeff KAT (from zisklib) plus pairing bilinearity and
// non-degeneracy (no blst needed; the KZG vectors in Layer 7 are the authority).

#include <cstdio>
#include <cstdint>
#include "../pairing.hpp"

using namespace zeg::bls;

static int g_fail = 0;
static void check(bool ok, const char* name) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", name); if (!ok) ++g_fail;
}

int main() {
    // --- twist_dbl_line KAT (fcalls_impl/bls12_381/twist.rs test_dbl_line_coeffs) ---
    {
        G2 q; q.x = {{{1,0,0,0,0,0}},{{0,0,0,0,0,0}}}; q.y = {{{2,0,0,0,0,0}},{{0,0,0,0,0,0}}};
        LineCoeffs lc = twist_dbl_line(q);
        Fp wl = {{14663509280485785601ULL,1657606133637906431ULL,10188441948600449179ULL,
                  10041189488738422287ULL,13282449870707802529ULL,1405348963235654899ULL}};
        Fp wm = {{17185665809301629612ULL,552535377879302143ULL,15693976698673184137ULL,
                  15644892545385841839ULL,10576397981472451381ULL,468449654411884966ULL}};
        check(fp_eq(lc.lambda.c0, wl) && fp_is_zero(lc.lambda.c1), "dbl_line λ KAT");
        check(fp_eq(lc.mu.c0, wm) && fp_is_zero(lc.mu.c1), "dbl_line μ KAT");
    }

    const G1 P = G1_GENERATOR;
    const G2 Q = G2_GENERATOR;
    std::printf("computing pairings (software, slow)...\n");

    Fp12 e = pairing(P, Q);
    check(!fp12_is_one(e), "e(P,Q) != 1 (non-degenerate)");

    // bilinearity: e([2]P, Q) == e(P, [2]Q)
    uint64_t two[4]={2,0,0,0};
    Fp12 e_2P_Q = pairing(g1_scalar_mul(P, two), Q);
    Fp12 e_P_2Q = pairing(P, g2_scalar_mul(Q, two));
    check(fp12_eq(e_2P_Q, e_P_2Q), "e(2P,Q) == e(P,2Q)");
    check(fp12_eq(e_2P_Q, fp12_sqr(e)), "e(2P,Q) == e(P,Q)^2");

    // e(-P,Q) == e(P,Q)^{-1}
    Fp12 e_negP_Q = pairing(g1_neg(P), Q);
    check(fp12_is_one(fp12_mul(e, e_negP_Q)), "e(P,Q)*e(-P,Q) == 1");

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

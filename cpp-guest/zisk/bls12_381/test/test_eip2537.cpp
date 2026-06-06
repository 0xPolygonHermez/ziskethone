// test_eip2537.cpp — host test of the EIP-2537 ops vs blst (authoritative oracle).
//   c++ -std=c++20 -O2 -I.. -I<blst/bindings> test_eip2537.cpp <libblst.a> -o /tmp/t && /tmp/t
// Uses the software backend (no ZEG_ZISK). Generates random G1/G2 points with
// blst, encodes EIP-2537, and compares our results against blst's.

#include <cstdio>
#include <cstdint>
#include <cstring>
extern "C" {
#include "blst.h"
}
#include "../eip2537.hpp"
#include "../g2_subgroup.hpp"

using namespace zeg::bls;
static int g_fail = 0;
static void check(bool ok, const char* n){ std::printf("%s %s\n", ok?"ok  ":"FAIL", n); if(!ok)++g_fail; }

static uint64_t s = 0xabcdef1234567890ULL;
static void rscalar(uint8_t out[32]){ for(int i=0;i<32;++i){ s=s*6364136223846793005ULL+1; out[i]=(uint8_t)(s>>32); } }

// blst → EIP-2537 encodings
static void enc_g1(const blst_p1_affine* a, uint8_t out[128]){
    std::memset(out,0,128);
    if (blst_p1_affine_is_inf(a)) return;
    blst_bendian_from_fp(out+16, &a->x); blst_bendian_from_fp(out+64+16, &a->y);
}
static void enc_g2(const blst_p2_affine* a, uint8_t out[256]){
    std::memset(out,0,256);
    if (blst_p2_affine_is_inf(a)) return;
    blst_bendian_from_fp(out+16,      &a->x.fp[0]); blst_bendian_from_fp(out+64+16,  &a->x.fp[1]);
    blst_bendian_from_fp(out+128+16,  &a->y.fp[0]); blst_bendian_from_fp(out+192+16, &a->y.fp[1]);
}
static void rand_g1(blst_p1_affine* a){ uint8_t sc[32]; rscalar(sc); blst_p1 p; blst_p1_mult(&p, blst_p1_generator(), sc, 255); blst_p1_to_affine(a,&p); }
static void rand_g2(blst_p2_affine* a){ uint8_t sc[32]; rscalar(sc); blst_p2 p; blst_p2_mult(&p, blst_p2_generator(), sc, 255); blst_p2_to_affine(a,&p); }

// our EIP-2537 g1_add/g2_add code path (same as the TU wrappers): parse+add+store
static bool my_g1_add(uint8_t out[128], const uint8_t a[128], const uint8_t b[128]) {
    G1 pa, pb; if (!g1_parse(a, a+64, &pa) || !g1_parse(b, b+64, &pb)) return false;
    g1_store(g1_add_complete(pa, pb), out, out+64); return true;
}
static bool my_g2_add(uint8_t out[256], const uint8_t a[256], const uint8_t b[256]) {
    G2 pa, pb; if (!g2_parse(a, a+128, &pa) || !g2_parse(b, b+128, &pb)) return false;
    g2_store(g2_add_complete(pa, pb), out, out+128); return true;
}

int main() {
    // ---- g1_add vs blst ----
    bool allg1 = true;
    for (int i = 0; i < 500; ++i) {
        blst_p1_affine a, b; rand_g1(&a); rand_g1(&b);
        uint8_t ea[128], eb[128]; enc_g1(&a, ea); enc_g1(&b, eb);
        uint8_t out[128];
        if (!my_g1_add(out, ea, eb)) { allg1=false; break; }
        // blst reference
        blst_p1 pa, pb, pr; blst_p1_from_affine(&pa,&a); blst_p1_from_affine(&pb,&b);
        blst_p1_add_or_double(&pr,&pa,&pb); blst_p1_affine ra; blst_p1_to_affine(&ra,&pr);
        uint8_t ref[128]; enc_g1(&ra, ref);
        if (std::memcmp(out, ref, 128) != 0) { allg1=false; break; }
    }
    check(allg1, "g1_add vs blst (500 random)");

    // ---- g2_add vs blst ----
    bool allg2 = true;
    for (int i = 0; i < 300; ++i) {
        blst_p2_affine a, b; rand_g2(&a); rand_g2(&b);
        uint8_t ea[256], eb[256]; enc_g2(&a, ea); enc_g2(&b, eb);
        uint8_t out[256];
        if (!my_g2_add(out, ea, eb)) { allg2=false; break; }
        blst_p2 pa, pb, pr; blst_p2_from_affine(&pa,&a); blst_p2_from_affine(&pb,&b);
        blst_p2_add_or_double(&pr,&pa,&pb); blst_p2_affine ra; blst_p2_to_affine(&ra,&pr);
        uint8_t ref[256]; enc_g2(&ra, ref);
        if (std::memcmp(out, ref, 256) != 0) { allg2=false; break; }
    }
    check(allg2, "g2_add vs blst (300 random)");

    // ---- B2: G2 subgroup check vs blst ----
    // in-subgroup points must be accepted
    bool sg = true;
    for (int i = 0; i < 50; ++i) {
        blst_p2_affine a; rand_g2(&a);
        uint8_t e[256]; enc_g2(&a, e); G2 p; g2_parse(e, e+128, &p);
        if (g2_is_on_subgroup(p) != (bool)blst_p2_affine_in_g2(&a) || !g2_is_on_subgroup(p)) { sg=false; break; }
    }
    check(sg, "g2 subgroup: in-subgroup accepted (vs blst)");
    // on-curve but NOT in subgroup must be rejected
    auto rfp = [](Fp* o){ for (int i=0;i<6;++i) o->c[i]=0; for(int i=0;i<5;++i){ s=s*6364136223846793005ULL+1; o->c[i]=s; } s=s*6364136223846793005ULL+1; o->c[5]=s>>8; };
    bool nsg = true; int tested = 0;
    for (int i = 0; i < 4000 && tested < 20; ++i) {
        Fp2 x; rfp(&x.c0); rfp(&x.c1);
        Fp2 rhs = fp2_add(fp2_mul(fp2_sqr(x), x), E2_B);   // x³ + 4(1+u)
        bool has; Fp2 y = fp2_sqrt(rhs, &has); if (!has) continue;
        G2 p{x, y};
        // build blst oracle affine from our coords
        blst_p2_affine ba; uint8_t t[48];
        fp_to_bytes_be(x.c0,t); blst_fp_from_bendian(&ba.x.fp[0],t);
        fp_to_bytes_be(x.c1,t); blst_fp_from_bendian(&ba.x.fp[1],t);
        fp_to_bytes_be(y.c0,t); blst_fp_from_bendian(&ba.y.fp[0],t);
        fp_to_bytes_be(y.c1,t); blst_fp_from_bendian(&ba.y.fp[1],t);
        if (!blst_p2_affine_on_curve(&ba)) continue;
        ++tested;
        if (g2_is_on_subgroup(p) != (bool)blst_p2_affine_in_g2(&ba)) { nsg=false; break; }
    }
    check(nsg && tested > 0, "g2 subgroup: on-curve non-subgroup rejected (vs blst)");

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

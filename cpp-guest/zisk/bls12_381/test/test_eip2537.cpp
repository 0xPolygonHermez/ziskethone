// test_eip2537.cpp — host test of the EIP-2537 ops vs blst (authoritative oracle).
//   c++ -std=c++20 -O2 -I.. -I<blst/bindings> test_eip2537.cpp <libblst.a> -o /tmp/t && /tmp/t
// On Apple Silicon force a native arm64 toolchain + arm64 libblst (the x86 blst
// uses ADX ops Rosetta traps on): arch -arm64 c++ -arch arm64 ...; build blst as
// `cc -arch arm64 -D__BLST_PORTABLE__ -c src/server.c build/assembly.S; ar rcs`.
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
    std::setvbuf(stdout, nullptr, _IONBF, 0);
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

    // ---- B3: g1_mul / g2_mul vs blst ----
    auto le32 = [](const uint8_t be[32], uint8_t le[32]){ for(int j=0;j<32;++j) le[j]=be[31-j]; };
    bool m1 = true;
    for (int i = 0; i < 200; ++i) {
        blst_p1_affine a; rand_g1(&a); uint8_t e[128]; enc_g1(&a, e);
        uint8_t sc[32]; rscalar(sc);
        uint8_t out[128];
        { G1 p; if(!g1_parse(e,e+64,&p)){m1=false;break;} if(!g1_is_on_subgroup(p)){m1=false;break;}
          uint64_t k[4]; scalar_be32(sc,k); g1_store(g1_scalar_mul(p,k),out,out+64); }
        uint8_t scle[32]; le32(sc,scle);
        blst_p1 pp,pr; blst_p1_from_affine(&pp,&a); blst_p1_mult(&pr,&pp,scle,256);
        blst_p1_affine ra; blst_p1_to_affine(&ra,&pr); uint8_t ref[128]; enc_g1(&ra,ref);
        if (std::memcmp(out,ref,128)!=0){m1=false;break;}
    }
    check(m1, "g1_mul vs blst (200 random)");

    bool m2 = true;
    for (int i = 0; i < 120; ++i) {
        blst_p2_affine a; rand_g2(&a); uint8_t e[256]; enc_g2(&a, e);
        uint8_t sc[32]; rscalar(sc);
        uint8_t out[256];
        { G2 p; if(!g2_parse(e,e+128,&p)){m2=false;break;} if(!g2_is_on_subgroup(p)){m2=false;break;}
          uint64_t k[4]; scalar_be32(sc,k); g2_store(g2_scalar_mul(p,k),out,out+128); }
        uint8_t scle[32]; le32(sc,scle);
        blst_p2 pp,pr; blst_p2_from_affine(&pp,&a); blst_p2_mult(&pr,&pp,scle,256);
        blst_p2_affine ra; blst_p2_to_affine(&ra,&pr); uint8_t ref[256]; enc_g2(&ra,ref);
        if (std::memcmp(out,ref,256)!=0){m2=false;break;}
    }
    check(m2, "g2_mul vs blst (120 random)");

    // ---- B3: g1_msm / g2_msm vs blst (Σ[kᵢ]Pᵢ, n=4) ----
    bool ms1 = true;
    for (int t = 0; t < 50 && ms1; ++t) {
        const int n = 4; uint8_t in[160*4]; blst_p1 sum; bool first = true; blst_p1_affine zero{};
        for (int i = 0; i < n; ++i) {
            blst_p1_affine a; rand_g1(&a); uint8_t e[128]; enc_g1(&a,e);
            uint8_t sc[32]; rscalar(sc);
            std::memcpy(in+i*160, e, 128); std::memcpy(in+i*160+128, sc, 32);
            uint8_t scle[32]; le32(sc,scle);
            blst_p1 pp,pr; blst_p1_from_affine(&pp,&a); blst_p1_mult(&pr,&pp,scle,256);
            if (first){ sum=pr; first=false; } else blst_p1_add_or_double(&sum,&sum,&pr);
        }
        // mine (same loop as TU g1_msm)
        G1 acc = G1_IDENTITY;
        for (int i = 0; i < n; ++i) {
            const uint8_t* ee = in+i*160; G1 p; g1_parse(ee,ee+64,&p);
            if (g1_is_identity(p)) continue;
            uint64_t k[4]; scalar_be32(ee+128,k); G1 prod=g1_scalar_mul(p,k);
            if (g1_is_identity(prod)) continue;
            acc = g1_is_identity(acc)?prod:g1_add_complete(acc,prod);
        }
        uint8_t out[128]; g1_store(acc,out,out+64);
        blst_p1_affine ra; blst_p1_to_affine(&ra,&sum); uint8_t ref[128]; enc_g1(&ra,ref);
        if (std::memcmp(out,ref,128)!=0) ms1=false;
    }
    check(ms1, "g1_msm vs blst (50× n=4)");

    bool ms2 = true;
    for (int t = 0; t < 30 && ms2; ++t) {
        const int n = 4; uint8_t in[288*4]; blst_p2 sum; bool first = true;
        for (int i = 0; i < n; ++i) {
            blst_p2_affine a; rand_g2(&a); uint8_t e[256]; enc_g2(&a,e);
            uint8_t sc[32]; rscalar(sc);
            std::memcpy(in+i*288, e, 256); std::memcpy(in+i*288+256, sc, 32);
            uint8_t scle[32]; le32(sc,scle);
            blst_p2 pp,pr; blst_p2_from_affine(&pp,&a); blst_p2_mult(&pr,&pp,scle,256);
            if (first){ sum=pr; first=false; } else blst_p2_add_or_double(&sum,&sum,&pr);
        }
        G2 acc = G2_IDENTITY;
        for (int i = 0; i < n; ++i) {
            const uint8_t* ee = in+i*288; G2 p; g2_parse(ee,ee+128,&p);
            if (g2_is_identity(p)) continue;
            uint64_t k[4]; scalar_be32(ee+256,k); G2 prod=g2_scalar_mul(p,k);
            if (g2_is_identity(prod)) continue;
            acc = g2_is_identity(acc)?prod:g2_add_complete(acc,prod);
        }
        uint8_t out[256]; g2_store(acc,out,out+128);
        blst_p2_affine ra; blst_p2_to_affine(&ra,&sum); uint8_t ref[256]; enc_g2(&ra,ref);
        if (std::memcmp(out,ref,256)!=0) ms2=false;
    }
    check(ms2, "g2_msm vs blst (30× n=4)");

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

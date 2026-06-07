// test_kzg.cpp — host unit test for the KZG verification core (software backend).
//   c++ -std=c++20 -O2 -I.. test_kzg.cpp -o /tmp/test_kzg && /tmp/test_kzg
//
// A non-trivial *valid* pairing instance can't be constructed on-host (it needs
// the secret τ), so the authoritative valid-path check is the real-block test in
// Layer 8. Here we cover the glue: a valid constant-polynomial proof, tampered/
// non-canonical inputs, and a case that exercises the full double-pairing path.

#include <cstdio>
#include <cstdint>
#include "../kzg.hpp"

using namespace zeg::bls;

static int g_fail = 0;
static void check(bool ok, const char* name) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", name); if (!ok) ++g_fail;
}
static void be32_u64(uint64_t v, uint8_t out[32]) { for (int i=0;i<32;++i) out[i]=0; for (int j=0;j<8;++j) out[31-j]=(uint8_t)(v>>(8*j)); }
static void compress_scalar_pt(uint64_t k, uint8_t out[48]) {     // compress [k]G1
    uint64_t kk[4]={k,0,0,0}; G1 p = g1_scalar_mul(G1_GENERATOR, kk); g1_compress(p, out);
}

int main() {
    uint8_t INF[48] = {0}; INF[0] = 0xc0;                          // compressed infinity

    // decompress(compress(P)) round-trip
    { uint8_t c[48]; compress_scalar_pt(7, c); G1 p; bool inf;
      check(g1_decompress(c, &p, &inf) && !inf, "decompress(compress([7]G)) ok"); }

    // Valid: constant polynomial p(x)=7 ⇒ C=[7]G1, y=7, any z, proof=O.
    { uint8_t C[48]; compress_scalar_pt(7, C);
      uint8_t y[32]; be32_u64(7, y); uint8_t z[32]; be32_u64(3, z);
      check(kzg_verify_core(z, y, C, INF), "valid constant-poly proof (proof=O)"); }

    // Invalid: wrong y (claim 8 for a commitment to 7).
    { uint8_t C[48]; compress_scalar_pt(7, C);
      uint8_t y[32]; be32_u64(8, y); uint8_t z[32]; be32_u64(3, z);
      check(!kzg_verify_core(z, y, C, INF), "wrong y rejected"); }

    // Non-canonical scalar z == r is rejected.
    { uint8_t C[48]; compress_scalar_pt(7, C);
      uint8_t y[32]; be32_u64(7, y);
      uint8_t z[32]; for (int i=0;i<4;++i){ uint64_t v=BLS_R[i]; for(int j=0;j<8;++j) z[31-(i*8+j)]=(uint8_t)(v>>(8*j)); }
      check(!kzg_verify_core(z, y, C, INF), "non-canonical z (==r) rejected"); }

    // Full double-pairing path (non-infinity everywhere); a random-ish instance
    // is invalid, so this must return false — and must not crash.
    { uint8_t C[48]; compress_scalar_pt(3, C);
      uint8_t P[48]; compress_scalar_pt(5, P);
      uint8_t y[32]; be32_u64(1, y); uint8_t z[32]; be32_u64(2, z);
      std::printf("running full double-pairing (software, slow)...\n");
      check(!kzg_verify_core(z, y, C, P), "full-pairing-path random instance rejected"); }

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

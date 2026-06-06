// test_g1.cpp — host test of BN254 G1 ops vs evmone's bn254 (authoritative EVM ref).
//   c++ -std=c++20 -O2 -I.. -I<evmone>/lib/evmone_precompiles -I<evmone>/include \
//       -I<intx>/include test_g1.cpp <evmone>/lib/evmone_precompiles/bn254.cpp -o /tmp/t && /tmp/t
// Software backend (no ZEG_ZISK). Generates random G1 points with evmone, then
// compares our add/double/opposite/scalar-mul/validate against evmone's.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <optional>
#include "bn254.hpp"          // evmone evmmax::bn254
#include "../g1.hpp"          // zeg::bn

using namespace zeg::bn;
namespace ev = evmmax::bn254;
static int g_fail = 0;
static void check(bool ok, const char* n){ std::printf("%s %s\n", ok?"ok  ":"FAIL", n); if(!ok)++g_fail; }

static uint64_t s = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(){ s = s*6364136223846793005ULL + 1442695040888963407ULL; return s; }
static intx::uint256 rscalar(){
    return (intx::uint256{rnd()}) | (intx::uint256{rnd()}<<64) | (intx::uint256{rnd()}<<128) | (intx::uint256{rnd()}<<192);
}

// evmone AffinePoint → 64-byte BE
static void enc(const ev::AffinePoint& p, uint8_t out[64]) {
    std::span<uint8_t,64> sp{out,64}; p.to_bytes(sp);
}
// 64-byte BE → our G1
static G1 parse(const uint8_t b[64]) { return { fp_from_bytes_be(b), fp_from_bytes_be(b+32) }; }
// our G1 → 64-byte BE
static void store(const G1& p, uint8_t out[64]) { fp_to_bytes_be(p.x,out); fp_to_bytes_be(p.y,out+32); }

static ev::AffinePoint rand_pt() {
    uint8_t g[64]={0}; g[31]=1; g[63]=2;            // generator (1,2)
    auto gen = ev::AffinePoint::from_bytes(std::span<const uint8_t,64>{g,64});
    return ev::mul(*gen, rscalar());
}

int main() {
    bool add=true, dbl=true, opp=true, val=true, mul=true, idn=true;
    for (int i=0;i<300 && add&&dbl&&opp&&mul&&val;++i) {
        ev::AffinePoint A = rand_pt(), B = rand_pt();
        uint8_t ea[64], eb[64]; enc(A,ea); enc(B,eb);
        G1 a = parse(ea), b = parse(eb);

        // validate / on-curve
        if (!g1_is_on_curve(a) || !ev::validate(A)) val=false;

        // add (distinct)
        { uint8_t mine[64], ref[64]; store(g1_add_complete(a,b), mine);
          enc(evmmax::ecc::add_affine(A,B), ref); if (std::memcmp(mine,ref,64)) add=false; }
        // double (A+A)
        { uint8_t mine[64], ref[64]; store(g1_add_complete(a,a), mine);
          enc(evmmax::ecc::add_affine(A,A), ref); if (std::memcmp(mine,ref,64)) dbl=false; }
        // opposite (A + (-A)) == infinity
        { G1 r = g1_add_complete(a, g1_neg(a)); if (!g1_is_identity(r)) opp=false; }
        // scalar mul: our (reduced k) vs evmone mul(A, m)
        { intx::uint256 m = rscalar();
          uint64_t k[4] = { (uint64_t)m, (uint64_t)(m>>64), (uint64_t)(m>>128), (uint64_t)(m>>192) };
          uint64_t kr[4]; fr_reduce(k, kr);
          uint8_t mine[64], ref[64]; store(g1_scalar_mul(a, kr), mine);
          enc(ev::mul(A, m), ref); if (std::memcmp(mine,ref,64)) mul=false; }
    }
    check(add, "g1 add (distinct) vs evmone (300)");
    check(dbl, "g1 double vs evmone");
    check(opp, "g1 A+(-A)==O");
    check(val, "g1 on-curve == evmone validate");
    check(mul, "g1 scalar_mul vs evmone mul");

    // identity handling: O+P==P, P+O==P, [0]P==O, [1]P==P
    { ev::AffinePoint A = rand_pt(); uint8_t ea[64]; enc(A,ea); G1 a=parse(ea);
      if (!g1_eq(g1_add_complete(G1_IDENTITY,a), a)) idn=false;
      if (!g1_eq(g1_add_complete(a,G1_IDENTITY), a)) idn=false;
      uint64_t z[4]={0,0,0,0}, one[4]={1,0,0,0};
      if (!g1_is_identity(g1_scalar_mul(a,z))) idn=false;
      if (!g1_eq(g1_scalar_mul(a,one), a)) idn=false; }
    check(idn, "g1 identity handling");

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

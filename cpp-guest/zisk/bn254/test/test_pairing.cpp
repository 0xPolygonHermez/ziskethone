// test_pairing.cpp — host test of the BN254 pairing vs evmone (EVM reference).
//   c++ -std=c++20 -O2 -I.. -I<evmone>/lib/evmone_precompiles -I<evmone>/include \
//       -I<intx>/include test_pairing.cpp <evmone>/lib/evmone_precompiles/bn254.cpp \
//       <evmone>/lib/evmone_precompiles/pairing/bn254/pairing.cpp -o /tmp/t && /tmp/t
// Software backend. Checks bilinearity with our pairing and compares our
// pairing_check (the ecPairing path) against evmone's on random + structured pairs.

#include <cstdio>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>
#include "bn254.hpp"            // evmone evmmax::bn254 (reference pairing_check)
#include "../pairing.hpp"       // zeg::bn

using namespace zeg::bn;
namespace ev = evmmax::bn254;
static int g_fail = 0;
static void check(bool ok, const char* n){ std::printf("%s %s\n", ok?"ok  ":"FAIL", n); if(!ok)++g_fail; }

static inline intx::uint256 u256(const Fp& f){
    return intx::uint256{f.c[0]}|(intx::uint256{f.c[1]}<<64)|(intx::uint256{f.c[2]}<<128)|(intx::uint256{f.c[3]}<<192);
}

// G1 generator (1,2); G2 generator from gen_g2.py.
static const G1 G1GEN = {{{1,0,0,0}},{{2,0,0,0}}};
static const G2 G2GEN = {{{0x46DEBD5CD992F6EDULL,0x674322D4F75EDADDULL,0x426A00665E5C4479ULL,0x1800DEEF121F1E76ULL},{0x97E485B7AEF312C2ULL,0xF1AA493335A9E712ULL,0x7260BFB731FB5D25ULL,0x198E9393920D483AULL}},{{0x4CE6CC0166FA7DAAULL,0xE3D1E7690C43D37BULL,0x4AAB71808DCB408FULL,0x12C85EA5DB8C6DEBULL},{0x55ACDADCD122975BULL,0xBC4B313370B38EF3ULL,0xEC9E99AD690C3395ULL,0x090689D0585FF075ULL}}};

static G1 g1mul(const G1& p, uint64_t k){ uint64_t kk[4]={k,0,0,0}; return g1_scalar_mul(p, kk); }
static G2 g2mul(const G2& p, uint64_t k){  // double-and-add for 64-bit scalar
    G2 r = G2_IDENTITY; G2 b = p;
    while (k){ if (k&1) r = g2_add(r,b); b = g2_dbl(b); k>>=1; }
    return r;
}

// our pairing_check (mirrors the wrapper) on our points.
static std::optional<bool> my_pc(const std::vector<std::pair<G1,G2>>& ps){
    Fp12 acc = FP12_ONE;
    for (auto& [g1,g2] : ps){
        if (!g1_in_field(g1)||!g2_in_field(g2)) return std::nullopt;
        bool i1=g1_is_identity(g1), i2=g2_is_identity(g2);
        if (!i1 && !g1_is_on_curve(g1)) return std::nullopt;
        if (!i2 && (!g2_is_on_curve(g2)||!g2_is_on_subgroup(g2))) return std::nullopt;
        if (!i1 && !i2) acc = fp12_mul(acc, miller_loop(g1,g2));
    }
    return fp12_is_one(final_exp(acc));
}
// evmone pairing_check on the same points.
static std::optional<bool> ev_pc(const std::vector<std::pair<G1,G2>>& ps){
    std::vector<std::pair<ev::Point, ev::ExtPoint>> pairs;
    for (auto& [g1,g2] : ps){
        ev::Point P{ u256(g1.x), u256(g1.y) };
        ev::ExtPoint Q{ { u256(g2.x.c0), u256(g2.x.c1) }, { u256(g2.y.c0), u256(g2.y.c1) } };
        pairs.emplace_back(P,Q);
    }
    return ev::pairing_check(pairs);
}

int main() {
    // ---- bilinearity (our pairing) ----
    Fp12 e = pairing(G1GEN, G2GEN);
    check(!fp12_is_one(e), "e(G1,G2) != 1 (non-degenerate)");
    check(fp12_is_one(fp12_mul(e, pairing(g1_neg(G1GEN), G2GEN))), "e(P,Q)·e(-P,Q)==1");
    check(fp12_eq(pairing(g1mul(G1GEN,2), G2GEN), fp12_sqr(e)), "e(2P,Q)==e(P,Q)²");
    check(fp12_eq(pairing(G1GEN, g2mul(G2GEN,2)), fp12_sqr(e)), "e(P,2Q)==e(P,Q)²");
    check(fp12_eq(pairing(g1mul(G1GEN,3), g2mul(G2GEN,5)), pairing(g1mul(G1GEN,15), G2GEN)),
          "e(3P,5Q)==e(15P,Q)");

    // ---- pairing_check vs evmone ----
    // classic: e(a·P, b·Q) · e(-(a·b)·P, Q) == 1
    { std::vector<std::pair<G1,G2>> ps = {
        { g1mul(G1GEN,6), g2mul(G2GEN,7) },
        { g1_neg(g1mul(G1GEN,42)), G2GEN } };
      auto a=my_pc(ps), b=ev_pc(ps);
      check(a.has_value()&&b.has_value()&&*a&&*b, "pairing_check true case == evmone (==1)"); }
    // random pairs vs evmone (mostly false)
    { bool okall=true; uint64_t s=12345;
      for (int t=0;t<6 && okall;++t){
        std::vector<std::pair<G1,G2>> ps;
        int n = 1 + (t%3);
        for (int i=0;i<n;++i){ s=s*6364136223846793005ULL+1; uint64_t a=(s>>20)%1000+1;
                               s=s*6364136223846793005ULL+1; uint64_t b=(s>>20)%1000+1;
                               ps.push_back({ g1mul(G1GEN,a), g2mul(G2GEN,b) }); }
        auto x=my_pc(ps), y=ev_pc(ps);
        if (!(x.has_value()&&y.has_value()&&*x==*y)) okall=false;
      }
      check(okall, "pairing_check vs evmone (random multi-pair)"); }
    // empty input → true
    { auto x=my_pc({}); check(x.has_value() && *x, "pairing_check empty == true"); }

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

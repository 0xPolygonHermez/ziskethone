// bn254_eip196.cpp — alt_bn128 / BN254 precompiles (ecAdd 0x06, ecMul 0x07,
// ecPairing 0x08) for the ZisK self-contained guest.
//
// Provides the evmmax::bn254 symbols the precompile dispatch calls
// (validate / mul / pairing_check) plus an explicit specialization of
// evmmax::ecc::add_affine for ECADD, all on the self-contained BN254 port
// (bn254/*.hpp) running on the ZisK precompiles + fcall hints. Replaces evmone's
// software bn254.cpp + pairing/bn254/pairing.cpp (excluded from the build).
//
// Boundary: evmone AffinePoint coords are FieldElement in Montgomery form — use
// .value() for the canonical uint256 and FE{uint256} to build results. Point /
// ExtPoint coords (pairing input) are plain uint256.

#include <evmone_precompiles/bn254.hpp>
#include "bn254/g1.hpp"
#include "bn254/pairing.hpp"
#include "bn254/add_affine_spec.hpp"
#ifdef ZKVM_BN254
#include <vector>
#include "zkvm_accelerators.h"
#endif

namespace {
using namespace zeg::bn;
using evmmax::bn254::AffinePoint;
using intx::uint256;

inline Fp to_fp(const uint256& v) {
    return Fp{{ (uint64_t)v, (uint64_t)(v >> 64), (uint64_t)(v >> 128), (uint64_t)(v >> 192) }};
}
inline uint256 to_u256(const Fp& f) {
    return uint256{f.c[0]} | (uint256{f.c[1]} << 64) | (uint256{f.c[2]} << 128) | (uint256{f.c[3]} << 192);
}
inline G1 to_g1(const AffinePoint& p) { return { to_fp(p.x.value()), to_fp(p.y.value()) }; }
[[maybe_unused]] inline AffinePoint to_ap(const G1& g) {
    return { evmmax::bn254::Curve::Fp{to_u256(g.x)}, evmmax::bn254::Curve::Fp{to_u256(g.y)} };
}
#ifdef ZKVM_BN254
// uint256 <-> 32 big-endian bytes (EF ABI field encoding).
inline void u256_to_be(const uint256& v, uint8_t b[32]) {
    for (int i = 0; i < 4; ++i) {
        uint64_t w = (uint64_t)(v >> (64 * (3 - i)));
        for (int j = 0; j < 8; ++j) b[i * 8 + j] = (uint8_t)(w >> (56 - 8 * j));
    }
}
inline uint256 be_to_u256(const uint8_t b[32]) {
    uint256 v = 0;
    for (int i = 0; i < 32; ++i) v = (v << 8) | uint256{b[i]};
    return v;
}
#endif
}  // namespace

namespace evmmax::bn254 {

// y² == x³ + 3, or the point at infinity.
bool validate(const AffinePoint& pt) noexcept {
    G1 p = to_g1(pt);
    return g1_is_identity(p) || g1_is_on_curve(p);
}

// [c]P. P is already field-valid + on-curve (caller validated). Cofactor 1, so no
// subgroup check; reduce c mod r then double-and-add.
AffinePoint mul(const AffinePoint& pt, const uint256& c) noexcept {
    G1 p = to_g1(pt);
    if (g1_is_identity(p)) return pt;
    if (c == 0) return {};
#ifdef ZKVM_BN254
    // EF standard C ABI: [c]P via the native .zisk bn254 mul (redirected by
    // elf2rom). The scalar is the raw 256-bit c (the .zisk reduces mod r).
    uint8_t pb[64], sb[32], r[64];
    u256_to_be(pt.x.value(), pb);
    u256_to_be(pt.y.value(), pb + 32);
    u256_to_be(c, sb);
    if (zkvm_bn254_g1_mul(reinterpret_cast<const zkvm_bn254_g1_point*>(pb),
                          reinterpret_cast<const zkvm_bn254_scalar*>(sb),
                          reinterpret_cast<zkvm_bn254_g1_point*>(r)) != ZKVM_EOK)
        return {};
    return { evmmax::bn254::Curve::Fp{be_to_u256(r)}, evmmax::bn254::Curve::Fp{be_to_u256(r + 32)} };
#else
    uint64_t k[4] = { (uint64_t)c, (uint64_t)(c >> 64), (uint64_t)(c >> 128), (uint64_t)(c >> 192) };
    uint64_t kr[4]; fr_reduce(k, kr);
    return to_ap(g1_scalar_mul(p, kr));
#endif
}

// ecPairing: ∏ e(Pᵢ,Qᵢ) == 1. Per-pair validate (field, on-curve, G2 subgroup),
// skip ∞ pairs, batch the Miller loops, then one final_exp. Point/ExtPoint coords
// are plain uint256 (not Montgomery). Mirrors evmone pairing/bn254/pairing.cpp.
std::optional<bool> pairing_check(std::span<const std::pair<Point, ExtPoint>> pairs) noexcept {
    if (pairs.empty()) return true;
#ifdef ZKVM_BN254
    // EF standard C ABI: ∏ e(Pᵢ,Qᵢ) == 1 via the native .zisk bn254 pairing.
    // EF pair = { g1[64] = Px|Py, g2[128] = EIP-197 imag-first x_imag|x_real|y_imag|y_real }.
    // evmone stores the Fp2 words SWAPPED vs input order (precompiles.cpp: q.x.first =
    // input[96] = x_real, q.x.second = input[64] = x_imag), so to rebuild the EIP-197
    // imag-first byte order the EF ABI expects we emit .second (imag) then .first (real).
    std::vector<uint8_t> buf(pairs.size() * 192);
    size_t off = 0;
    for (const auto& [P, Q] : pairs) {
        u256_to_be(P.x,        buf.data() + off);
        u256_to_be(P.y,        buf.data() + off + 32);
        u256_to_be(Q.x.second, buf.data() + off + 64);   // x_imag
        u256_to_be(Q.x.first,  buf.data() + off + 96);   // x_real
        u256_to_be(Q.y.second, buf.data() + off + 128);  // y_imag
        u256_to_be(Q.y.first,  buf.data() + off + 160);  // y_real
        off += 192;
    }
    bool ok = false;
    if (zkvm_bn254_pairing(reinterpret_cast<const zkvm_bn254_pairing_pair*>(buf.data()),
                           pairs.size(), &ok) != ZKVM_EOK)
        return std::nullopt;
    return ok;
#else
    Fp12 acc = FP12_ONE;
    for (const auto& [P, Q] : pairs) {
        G1 g1{ to_fp(P.x), to_fp(P.y) };
        G2 g2{ { to_fp(Q.x.first), to_fp(Q.x.second) }, { to_fp(Q.y.first), to_fp(Q.y.second) } };
        if (!g1_in_field(g1) || !g2_in_field(g2)) return std::nullopt;
        bool g1inf = g1_is_identity(g1), g2inf = g2_is_identity(g2);
        if (!g1inf && !g1_is_on_curve(g1)) return std::nullopt;
        if (!g2inf && (!g2_is_on_curve(g2) || !g2_is_on_subgroup(g2))) return std::nullopt;
        if (!g1inf && !g2inf) acc = fp12_mul(acc, miller_loop(g1, g2));
    }
    return fp12_is_one(final_exp(acc));
#endif
}

}  // namespace evmmax::bn254

// ECADD: route the generic add_affine template through the accelerated G1 add.
namespace evmmax::ecc {
template <>
AffinePoint<evmmax::bn254::Curve> add_affine<evmmax::bn254::Curve>(
    const AffinePoint<evmmax::bn254::Curve>& p,
    const AffinePoint<evmmax::bn254::Curve>& q) noexcept {
#ifdef ZKVM_BN254
    // EF standard C ABI: P + Q via the native .zisk bn254 g1 add (redirected by
    // elf2rom). Coords are canonical big-endian; the .zisk handles identities.
    uint8_t a[64], b[64], r[64];
    u256_to_be(p.x.value(), a);
    u256_to_be(p.y.value(), a + 32);
    u256_to_be(q.x.value(), b);
    u256_to_be(q.y.value(), b + 32);
    if (zkvm_bn254_g1_add(reinterpret_cast<const zkvm_bn254_g1_point*>(a),
                          reinterpret_cast<const zkvm_bn254_g1_point*>(b),
                          reinterpret_cast<zkvm_bn254_g1_point*>(r)) != ZKVM_EOK)
        return {};
    return { evmmax::bn254::Curve::Fp{be_to_u256(r)}, evmmax::bn254::Curve::Fp{be_to_u256(r + 32)} };
#else
    return to_ap(g1_add_complete(to_g1(p), to_g1(q)));
#endif
}
}  // namespace evmmax::ecc

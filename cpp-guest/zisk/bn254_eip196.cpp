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
#include "bn254/add_affine_spec.hpp"
// pairing_check (ecPairing) is added in N4.

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
inline AffinePoint to_ap(const G1& g) {
    return { evmmax::bn254::Curve::Fp{to_u256(g.x)}, evmmax::bn254::Curve::Fp{to_u256(g.y)} };
}
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
    uint64_t k[4] = { (uint64_t)c, (uint64_t)(c >> 64), (uint64_t)(c >> 128), (uint64_t)(c >> 192) };
    uint64_t kr[4]; fr_reduce(k, kr);
    return to_ap(g1_scalar_mul(p, kr));
}

}  // namespace evmmax::bn254

// ECADD: route the generic add_affine template through the accelerated G1 add.
namespace evmmax::ecc {
template <>
AffinePoint<evmmax::bn254::Curve> add_affine<evmmax::bn254::Curve>(
    const AffinePoint<evmmax::bn254::Curve>& p,
    const AffinePoint<evmmax::bn254::Curve>& q) noexcept {
    return to_ap(g1_add_complete(to_g1(p), to_g1(q)));
}
}  // namespace evmmax::ecc

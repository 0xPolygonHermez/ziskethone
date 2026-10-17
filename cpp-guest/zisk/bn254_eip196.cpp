// bn254_eip196.cpp — alt_bn128 / BN254 precompiles (ecAdd 0x06, ecMul 0x07,
// ecPairing 0x08) for the ZisK build, through the EF zkVM accelerator ABI.
//
// Provides the evmmax::bn254 symbols the precompile dispatch calls
// (validate / mul / pairing_check) plus an explicit specialization of
// evmmax::ecc::add_affine for ECADD, each as zkvm_bn254_* calls. Replaces evmone's
// software bn254.cpp + pairing/bn254/pairing.cpp (excluded from the build).
//
// Boundary: evmone AffinePoint coords are FieldElement in Montgomery form — use
// .value() for the canonical uint256 and FE{uint256} to build results. Point /
// ExtPoint coords (pairing input) are plain uint256. The EF ABI takes 32-byte
// big-endian field elements.

#include <vector>

#include <evmone_precompiles/bn254.hpp>
#include "bn254/add_affine_spec.hpp"
#include "zkvm_accelerators.h"

namespace {
using evmmax::bn254::AffinePoint;
using intx::uint256;

// An AffinePoint as the EF 64-byte G1 encoding x || y.
inline void store_g1(const AffinePoint& p, uint8_t b[64]) {
    intx::be::unsafe::store(b, p.x.value());
    intx::be::unsafe::store(b + 32, p.y.value());
}
inline AffinePoint load_g1(const uint8_t b[64]) {
    return { evmmax::bn254::Curve::Fp{intx::be::unsafe::load<uint256>(b)},
             evmmax::bn254::Curve::Fp{intx::be::unsafe::load<uint256>(b + 32)} };
}
}  // namespace

namespace evmmax::bn254 {

// y² == x³ + 3, or the point at infinity. zkvm_bn254_g1_add checks both inputs (the
// all-zero identity first, then coordinates < p and on the curve) and fails on an
// invalid one, so adding the identity is exactly this check.
bool validate(const AffinePoint& pt) noexcept {
    zkvm_bn254_g1_point p, o = {}, r;
    store_g1(pt, p.data);
    return zkvm_bn254_g1_add(&p, &o, &r) == ZKVM_EOK;
}

// [c]P. P is already field-valid + on-curve (caller validated). The scalar is the
// raw 256-bit c: zkvm_bn254_g1_mul reduces it mod r.
AffinePoint mul(const AffinePoint& pt, const uint256& c) noexcept {
    zkvm_bn254_g1_point p, r;
    zkvm_bn254_scalar k;
    store_g1(pt, p.data);
    intx::be::unsafe::store(k.data, c);
    if (zkvm_bn254_g1_mul(&p, &k, &r) != ZKVM_EOK)
        return {};
    return load_g1(r.data);
}

// ecPairing: ∏ e(Pᵢ,Qᵢ) == 1. zkvm_bn254_pairing validates every pair itself (field,
// on-curve, G2 subgroup) and fails on an invalid one, which maps to nullopt.
// EF pair = { g1[64] = Px|Py, g2[128] = EIP-197 imag-first x_imag|x_real|y_imag|y_real }.
// evmone stores the Fp2 words SWAPPED vs input order (precompiles.cpp: q.x.first =
// input[96] = x_real, q.x.second = input[64] = x_imag), so to rebuild the EIP-197
// imag-first byte order the EF ABI expects we emit .second (imag) then .first (real).
std::optional<bool> pairing_check(std::span<const std::pair<Point, ExtPoint>> pairs) noexcept {
    if (pairs.empty()) return true;
    static_assert(sizeof(zkvm_bn254_pairing_pair) == 192);
    std::vector<zkvm_bn254_pairing_pair> buf(pairs.size());
    uint8_t* b = buf.data()->g1.data;
    for (const auto& [P, Q] : pairs) {
        intx::be::unsafe::store(b, P.x);
        intx::be::unsafe::store(b + 32, P.y);
        intx::be::unsafe::store(b + 64, Q.x.second);   // x_imag
        intx::be::unsafe::store(b + 96, Q.x.first);    // x_real
        intx::be::unsafe::store(b + 128, Q.y.second);  // y_imag
        intx::be::unsafe::store(b + 160, Q.y.first);   // y_real
        b += 192;
    }
    bool ok = false;
    if (zkvm_bn254_pairing(buf.data(), pairs.size(), &ok) != ZKVM_EOK)
        return std::nullopt;
    return ok;
}

}  // namespace evmmax::bn254

// ECADD: route the generic add_affine template through zkvm_bn254_g1_add. Coords are
// canonical; the ABI handles identities.
namespace evmmax::ecc {
template <>
AffinePoint<evmmax::bn254::Curve> add_affine<evmmax::bn254::Curve>(
    const AffinePoint<evmmax::bn254::Curve>& p,
    const AffinePoint<evmmax::bn254::Curve>& q) noexcept {
    zkvm_bn254_g1_point a, b, r;
    store_g1(p, a.data);
    store_g1(q, b.data);
    if (zkvm_bn254_g1_add(&a, &b, &r) != ZKVM_EOK)
        return {};
    return load_g1(r.data);
}
}  // namespace evmmax::ecc

// add_affine_spec.hpp — declares the explicit specialization of evmone's
// evmone::crypto::ecc::add_affine for the BN254 curve, so the ECADD precompile dispatch
// (test/state/precompiles.cpp) routes through our ZisK-accelerated G1 add instead
// of the generic ModArith software template. This header is force-included into
// precompiles.cpp's compile (see CMakeLists) so the specialization is visible at
// the point of instantiation; the definition lives in bn254_eip196.cpp.
//
// It also makes the BN254 base field hold canonical values: from_bytes stores the
// input as is and value() returns it, so the ECADD/ECMUL/ECPAIRING dispatch skips
// evmone's software Montgomery conversions (the zkvm_bn254_* ABI takes and returns
// canonical big-endian coordinates). Only valid because nothing in the ZisK build
// does BN254 field arithmetic: bn254.cpp and the software pairing are excluded, and
// every element the dispatch reads comes from from_bytes. Elements built with the
// constructor (Fp{v}, the Curve constants) are still in Montgomery form, so never
// read one with value().

#pragma once

#include <evmone_precompiles/bn254.hpp>

namespace evmone::crypto::ecc {
template <>
AffinePoint<evmone::crypto::bn254::Curve> add_affine<evmone::crypto::bn254::Curve>(
    const AffinePoint<evmone::crypto::bn254::Curve>& p,
    const AffinePoint<evmone::crypto::bn254::Curve>& q) noexcept;
}  // namespace evmone::crypto::ecc

namespace evmone::crypto::ecc {
template <>
template <>
constexpr std::optional<bn254::Fq> bn254::Fq::from_bytes<bn254::Fq::Range::full>(
    std::span<const uint8_t, sizeof(intx::uint256)> b) noexcept {
    const auto x = intx::be::load<intx::uint256>(b);
    if (x >= ORDER) [[unlikely]]
        return std::nullopt;
    return wrap(x);
}

template <>
constexpr intx::uint256 bn254::Fq::value() const noexcept {
    return value_;
}
}  // namespace evmone::crypto::ecc

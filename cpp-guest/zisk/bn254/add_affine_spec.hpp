// add_affine_spec.hpp — declares the explicit specialization of evmone's
// evmone::crypto::ecc::add_affine for the BN254 curve, so the ECADD precompile dispatch
// (test/state/precompiles.cpp) routes through our ZisK-accelerated G1 add instead
// of the generic ModArith software template. This header is force-included into
// precompiles.cpp's compile (see CMakeLists) so the specialization is visible at
// the point of instantiation; the definition lives in bn254_eip196.cpp.

#pragma once

#include <evmone_precompiles/bn254.hpp>

namespace evmone::crypto::ecc {
template <>
AffinePoint<evmone::crypto::bn254::Curve> add_affine<evmone::crypto::bn254::Curve>(
    const AffinePoint<evmone::crypto::bn254::Curve>& p,
    const AffinePoint<evmone::crypto::bn254::Curve>& q) noexcept;
}  // namespace evmone::crypto::ecc

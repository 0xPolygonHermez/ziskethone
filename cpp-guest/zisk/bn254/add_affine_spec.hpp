// add_affine_spec.hpp — declares the explicit specialization of evmone's
// evmmax::ecc::add_affine for the BN254 curve, so the ECADD precompile dispatch
// (test/state/precompiles.cpp) routes through our ZisK-accelerated G1 add instead
// of the generic ModArith software template. This header is force-included into
// precompiles.cpp's compile (see CMakeLists) so the specialization is visible at
// the point of instantiation; the definition lives in bn254_eip196.cpp.

#pragma once

#include <evmone_precompiles/bn254.hpp>

namespace evmmax::ecc {
template <>
AffinePoint<evmmax::bn254::Curve> add_affine<evmmax::bn254::Curve>(
    const AffinePoint<evmmax::bn254::Curve>& p,
    const AffinePoint<evmmax::bn254::Curve>& q) noexcept;
}  // namespace evmmax::ecc

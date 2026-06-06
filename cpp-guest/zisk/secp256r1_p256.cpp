// secp256r1_p256.cpp — secp256r1 / P-256 ECDSA precompile (p256verify 0x100,
// RIP-7212 / EIP-7951) for the ZisK self-contained guest.
//
// Provides evmmax::secp256r1::verify (the symbol p256verify_execute calls) on the
// self-contained P-256 port (secp256r1/p256.hpp) running on the ZisK secp256r1
// precompiles + fcall hints. Replaces evmone's software secp256r1.cpp (excluded
// from the build). Inputs are big-endian (hash256 / intx::uint256); convert to
// little-endian u64[4] limbs at the boundary.

#include <evmone_precompiles/secp256r1.hpp>
#include "secp256r1/p256.hpp"

namespace {
inline void to_limbs(const intx::uint256& v, uint64_t o[4]) {
    o[0] = (uint64_t)v; o[1] = (uint64_t)(v >> 64); o[2] = (uint64_t)(v >> 128); o[3] = (uint64_t)(v >> 192);
}
}  // namespace

namespace evmmax::secp256r1 {

bool verify(const ethash::hash256& h, const uint256& r, const uint256& s, const uint256& qx,
    const uint256& qy) noexcept {
    uint64_t z[4], rr[4], ss[4], pk[8];
    to_limbs(intx::be::load<intx::uint256>(h.bytes), z);
    to_limbs(r, rr);
    to_limbs(s, ss);
    to_limbs(qx, pk);
    to_limbs(qy, pk + 4);
    return zeg::r1::ecdsa_verify(pk, z, rr, ss);
}

}  // namespace evmmax::secp256r1

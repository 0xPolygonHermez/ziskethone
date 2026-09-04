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
#ifdef ZKVM_SECP256R1
#include "zkvm_accelerators.h"
#endif

namespace {
[[maybe_unused]] inline void to_limbs(const intx::uint256& v, uint64_t o[4]) {
    o[0] = (uint64_t)v; o[1] = (uint64_t)(v >> 64); o[2] = (uint64_t)(v >> 128); o[3] = (uint64_t)(v >> 192);
}
#ifdef ZKVM_SECP256R1
// intx::uint256 (LE limbs) -> 32 big-endian bytes (EF ABI field encoding).
inline void zkvm_u256_to_be32(const intx::uint256& v, uint8_t be[32]) {
    const uint64_t limb[4] = {(uint64_t)v, (uint64_t)(v >> 64), (uint64_t)(v >> 128), (uint64_t)(v >> 192)};
    for (int i = 0; i < 4; i++) {
        uint64_t w = limb[3 - i];
        for (int j = 0; j < 8; j++) be[i * 8 + j] = (uint8_t)(w >> (56 - 8 * j));
    }
}
#endif
}  // namespace

namespace evmmax::secp256r1 {

bool verify(const ethash::hash256& h, const uint256& r, const uint256& s, const uint256& qx,
    const uint256& qy) noexcept {
#ifdef ZKVM_SECP256R1
    // EF standard C ABI: marshal r/s/qx/qy (LE-limb uint256) to big-endian bytes and
    // call the native .zisk secp256r1 verify (redirected by elf2rom). h.bytes is
    // already the 32-byte big-endian message hash, used as-is.
    uint8_t sig[64], pub[64];
    zkvm_u256_to_be32(r, sig);
    zkvm_u256_to_be32(s, sig + 32);
    zkvm_u256_to_be32(qx, pub);
    zkvm_u256_to_be32(qy, pub + 32);
    bool ok = false;
    zkvm_status st = zkvm_secp256r1_verify(
        reinterpret_cast<const zkvm_secp256r1_hash*>(h.bytes),
        reinterpret_cast<const zkvm_secp256r1_signature*>(sig),
        reinterpret_cast<const zkvm_secp256r1_pubkey*>(pub), &ok);
    return st == ZKVM_EOK && ok;
#else
    uint64_t z[4], rr[4], ss[4], pk[8];
    to_limbs(intx::be::load<intx::uint256>(h.bytes), z);
    to_limbs(r, rr);
    to_limbs(s, ss);
    to_limbs(qx, pk);
    to_limbs(qy, pk + 4);
    return zeg::r1::ecdsa_verify(pk, z, rr, ss);
#endif
}

}  // namespace evmmax::secp256r1

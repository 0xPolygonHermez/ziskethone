// Thin re-declaration of the ZisK lib-c crypto syscalls the guest needs.
// Mirrors the C ABI from `zisk/lib-c/c/src/ec/ec.hpp` so the rest of the
// guest can call them without taking a build-time dependency on the
// lib-c include path. The actual symbols are provided by ZisK lib-c on
// the zkVM target; the host build links a weak stub that aborts (see
// `src/zisk_crypto_host_stub.cpp`).
//
// Limb convention: every `uint64_t* xxx` is a little-endian-ordered
// array of 64-bit native-byte-order limbs (limb[0] is the least
// significant 64 bits of the 256-bit integer). This matches the
// `mpz_import(..., -1, 8, -1, ...)` decoding inside lib-c's
// `array2fe` (see `zisk/lib-c/c/src/common/utils.hpp:47`).

#pragma once

#include <cstdint>

#include <evmc/evmc.hpp>

extern "C" {

// Computes p = u1·G + u2·PK (over secp256k1) and writes its (x, y)
// affine coordinates as 8 × uint64 limbs into `result`. The caller is
// responsible for the final `result.x mod n == r` ECDSA check — this
// function always returns 0. See `zisk/lib-c/c/src/ec/ec.cpp:196`.
int secp256k1_ecdsa_verify(
    const uint64_t* pk,     // 8 limbs: pk_x[4] || pk_y[4]
    const uint64_t* z,      // 4 limbs: message hash
    const uint64_t* r,      // 4 limbs
    const uint64_t* s,      // 4 limbs
    uint64_t*       result  // 8 limbs: x[4] || y[4]
);

} // extern "C"

namespace zeg {

// Verify ECDSA(secp256k1) signature against `pubkey` (64 B, x || y, BE)
// and return signer = keccak256(pubkey)[12:]. Aborts via zeg::fatal on
// any verification failure (the wrapped lib-c call always returns 0;
// the check is on `result.x mod n == r`).
//
// Used by the EIP-7702 authorization-list walk to recover each auth's
// signer address.
evmc::address verify_signature_and_get_signer(
    const uint8_t*         pubkey,
    const evmc::bytes32&   signing_hash,
    const evmc::uint256be& r,
    const evmc::uint256be& s);

} // namespace zeg

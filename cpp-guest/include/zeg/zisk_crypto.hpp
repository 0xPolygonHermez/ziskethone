// Thin re-declaration of the secp256k1 ECDSA C ABI the guest needs (the limb
// convention originates from ZisK lib-c's `zisk/lib-c/c/src/ec/ec.hpp`). The
// symbols come from the single shared implementation in
// `cpp-guest/zisk/secp256k1.cpp` on every build: ZisK precompiles + verified
// fcall hints on the zkVM target, its portable software backend
// (ZEG_SECP256K1_SW) on the host.
//
// Limb convention: every `uint64_t* xxx` is a little-endian-ordered
// array of 64-bit native-byte-order limbs (limb[0] is the least
// significant 64 bits of the 256-bit integer). This matches the
// `mpz_import(..., -1, 8, -1, ...)` decoding inside lib-c's
// `array2fe` (see `zisk/lib-c/c/src/common/utils.hpp:47`).

#pragma once

#include <cstdint>
#include <cstring>

#include <evmc/evmc.hpp>

extern "C" {

// Recover the signing public key from an ECDSA(secp256k1) signature. Given the
// message hash `z`, signature (`r`, `s`) and recovery id `recid` (0 or 1),
// writes the recovered pubkey (x[4] || y[4]) into `pubkey` and returns 0.
// Returns non-zero when the signature is not recoverable. Implemented by the
// single shared `cpp-guest/zisk/secp256k1.cpp` on every build (ZisK
// precompiles + verified fcall hints on the zkVM, software on the host).
// Used for everything that derives a signer: tx senders, EIP-7702
// authorization signers, and the EVM ECRECOVER precompile.
int secp256k1_ecdsa_recover(
    const uint64_t* z,      // 4 limbs: message hash
    const uint64_t* r,      // 4 limbs
    const uint64_t* s,      // 4 limbs
    unsigned        recid,  // 0 or 1
    uint64_t*       pubkey  // 8 limbs: x[4] || y[4]
);

} // extern "C"

namespace zeg {

// Recover the signer address from the message `hash`, signature (`r`, `s`)
// and recovery id `recid` (0 or 1) — tx senders, EIP-7702 auth signers, and
// the EVM ECRECOVER precompile all derive signers through this. On success
// writes signer = keccak256(pubkey)[12:] into `out` and returns true; returns
// false when the signature is not recoverable (caller emits empty output).
// Caller is responsible for the r/s range and v validity per EVM rules — this
// forwards to secp256k1_ecdsa_recover, which also rejects out-of-range inputs.
bool ecrecover_address(
    const evmc::bytes32&   hash,
    const evmc::uint256be& r,
    const evmc::uint256be& s,
    unsigned               recid,
    evmc::address&         out);

// EIP-2 canonical signature bound: a signature's s must lie in [1, secp256k1n/2]
// or the signature is malleable and every conforming EL rejects the block.
// secp256k1n/2 = floor(N/2)
//   = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
inline constexpr uint8_t kSecp256k1NHalf[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
};

// True iff `s` (big-endian 32-byte) is in [1, secp256k1n/2]. Transaction
// senders (EIP-2) and EIP-7702 authorization signers must be low-s; the
// ECRECOVER precompile (0x01) must NOT apply this — it stays malleable by spec.
inline bool is_canonical_low_s(const evmc::uint256be& s) {
    if (std::memcmp(s.bytes, kSecp256k1NHalf, 32) > 0) return false;  // s > N/2
    for (uint8_t b : s.bytes) {
        if (b != 0) return true;                                      // s != 0
    }
    return false;                                                    // s == 0
}

} // namespace zeg

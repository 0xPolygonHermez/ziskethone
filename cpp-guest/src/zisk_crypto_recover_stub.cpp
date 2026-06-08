// Host-only weak stub for ZisK's secp256k1_ecdsa_recover (EVM ECRECOVER).
//
// The real implementations live in:
//   - zkVM target:      cpp-guest/zisk/secp256k1.cpp (accelerated)
//   - host libsecp256k1: src/zisk_crypto_libsecp256k1.cpp (recover_compact)
//
// The `zisk-libc` and `stub` host backends have no recover of their own
// (ZisK lib-c only exports verify), so this stub provides a definition that
// lets those builds link and aborts loudly if ECRECOVER is ever exercised.
// It is recover-only (no verify) so it can be added to the `zisk-libc` link
// without shadowing libziskc's archive `secp256k1_ecdsa_verify`. `weak` lets a
// real symbol override it if one is ever linked.

#include "zeg/zisk_crypto.hpp"

#include "zeg/fatal.hpp"

extern "C" __attribute__((weak)) int secp256k1_ecdsa_recover(
    const uint64_t*, const uint64_t*, const uint64_t*, unsigned, uint64_t*) {
    zeg::fatal("secp256k1_ecdsa_recover: host stub reached "
               "(ECRECOVER not supported by this secp backend)");
    return -1;
}

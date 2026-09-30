// secp256r1_p256.cpp — secp256r1 / P-256 ECDSA precompile (p256verify 0x100,
// RIP-7212 / EIP-7951) for the ZisK build, through the EF zkVM accelerator ABI.
//
// Provides evmmax::secp256r1::verify (the symbol p256verify_execute calls) as one
// zkvm_secp256r1_verify call, replacing evmone's software secp256r1.cpp (excluded
// from the build). The EF ABI takes big-endian bytes: h is already the 32-byte
// big-endian message hash; r, s and the public key are stored big-endian.

#include <evmone_precompiles/secp256r1.hpp>
#include "zkvm_accelerators.h"

namespace evmmax::secp256r1 {

bool verify(const ethash::hash256& h, const uint256& r, const uint256& s, const uint256& qx,
    const uint256& qy) noexcept {
    uint8_t sig[64], pub[64];
    intx::be::unsafe::store(sig, r);
    intx::be::unsafe::store(sig + 32, s);
    intx::be::unsafe::store(pub, qx);
    intx::be::unsafe::store(pub + 32, qy);
    bool ok = false;
    const zkvm_status st = zkvm_secp256r1_verify(
        reinterpret_cast<const zkvm_secp256r1_hash*>(h.bytes),
        reinterpret_cast<const zkvm_secp256r1_signature*>(sig),
        reinterpret_cast<const zkvm_secp256r1_pubkey*>(pub), &ok);
    return st == ZKVM_EOK && ok;
}

}  // namespace evmmax::secp256r1

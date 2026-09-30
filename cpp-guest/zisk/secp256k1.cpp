// secp256k1.cpp — secp256k1 ECDSA recover, two implementations of the same ABI
// selected by target (ZEG_ZISK):
//
//   ZisK guest (ZEG_ZISK) : one zkvm_secp256k1_ecrecover call, the EF zkVM
//                           accelerator ABI (a zkvmcall thunk the transpiler
//                           turns into a jump to the native .zisk routine).
//   host (!ZEG_ZISK)      : delegates to evmone's
//                           evmmax::secp256k1::secp256k1_ecdsa_recover (intx,
//                           projective coords). The host only needs a correct
//                           fast answer (it proves nothing), and evmone is the
//                           reference implementation, so it doubles as the
//                           differential oracle for the ZisK path.
//
// Public ABI (see zeg/zisk_crypto.hpp):
//   int secp256k1_ecdsa_recover(z, r, s, recid, pubkey)
//       full ECDSA public-key recovery — every signer derivation in the guest
//       (tx senders, EIP-7702 auth signers, the EVM ECRECOVER precompile) goes
//       through it via zeg::ecrecover_address. Limbs: uint64_t[4] little-endian
//       (limb[0] = low 64 bits); points are uint64_t[8] = x[4] || y[4]. Returns 0
//       on success, 1 when the signature is not recoverable.

#include <cstdint>

namespace {
// LE limbs (uint64_t[4], limb[0] = low) <-> 32 big-endian bytes, for the evmone and
// EF ABI boundaries (both take/return big-endian).
inline void limbs_to_be(const uint64_t l[4], uint8_t be[32]) {
    for (int i = 0; i < 4; ++i) {
        const uint64_t w = l[3 - i];
        for (int j = 0; j < 8; ++j) be[i * 8 + j] = static_cast<uint8_t>(w >> (8 * (7 - j)));
    }
}
inline void be_to_limbs(const uint8_t be[32], uint64_t l[4]) {
    for (int i = 0; i < 4; ++i) {
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j) w = (w << 8) | be[i * 8 + j];
        l[3 - i] = w;
    }
}
}  // namespace

#if !defined(ZEG_ZISK)
// ===========================================================================
// Host: delegate to evmone's reference recover.
// ===========================================================================
#include <evmone_precompiles/secp256k1.hpp>

extern "C" int secp256k1_ecdsa_recover(const uint64_t* z, const uint64_t* r,
                                       const uint64_t* s, unsigned recid,
                                       uint64_t* pubkey) {
    uint8_t zb[32], rb[32], sb[32];
    limbs_to_be(z, zb);
    limbs_to_be(r, rb);
    limbs_to_be(s, sb);
    // evmone validates r,s in [1,n-1] and returns nullopt when no point exists —
    // identical precompile semantics to the ZisK path below.
    const auto pt = evmmax::secp256k1::secp256k1_ecdsa_recover(zb, rb, sb, recid != 0);
    if (!pt.has_value())
        return 1;  // not recoverable
    uint8_t pk[64];
    pt->to_bytes(pk);  // x || y, 64 big-endian bytes (Montgomery -> normal)
    be_to_limbs(pk, pubkey);
    be_to_limbs(pk + 32, pubkey + 4);
    return 0;
}

#else  // ===================== ZisK guest =====================================
#include "zkvm_accelerators.h"

extern "C" int secp256k1_ecdsa_recover(const uint64_t* z, const uint64_t* r,
                                       const uint64_t* s, unsigned recid,
                                       uint64_t* pubkey) {
    if (recid > 1) return 1;
    // The ABI rejects r or s outside [1, n-1] and signatures with no recoverable
    // point, both as a non-EOK status.
    uint8_t msg[32], sig[64], out[64];
    limbs_to_be(z, msg);
    limbs_to_be(r, sig);
    limbs_to_be(s, sig + 32);
    if (zkvm_secp256k1_ecrecover(reinterpret_cast<const zkvm_secp256k1_hash*>(msg),
                                 reinterpret_cast<const zkvm_secp256k1_signature*>(sig),
                                 static_cast<uint8_t>(recid),
                                 reinterpret_cast<zkvm_secp256k1_pubkey*>(out)) != ZKVM_EOK)
        return 1;
    be_to_limbs(out, pubkey);
    be_to_limbs(out + 32, pubkey + 4);
    return 0;
}

#endif  // ZEG_ZISK

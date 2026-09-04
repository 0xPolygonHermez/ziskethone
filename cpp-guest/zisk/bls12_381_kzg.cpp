// bls12_381_kzg.cpp — EIP-4844 KZG point-evaluation precompile (0x0a) for the
// ZisK build. Provides the one symbol evmone's point_evaluation_execute calls:
//
//   evmone::crypto::kzg_verify_proof(versioned_hash, z, y, commitment, proof)
//
// It does the versioned-hash check (0x01 || sha256(commitment)[1:]) using the
// sha256 already in the build, then delegates the BLS12-381 pairing check to the
// self-contained port in bls12_381/ (kzg_verify_core), which runs on the ZisK
// precompiles + fcall hints. Replaces the failure stub in precompile_stubs.cpp.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <evmone_precompiles/kzg.hpp>     // declaration + VERSIONED_HASH_VERSION_KZG
#include <evmone_precompiles/sha256.hpp>  // evmone::crypto::sha256

#include "bls12_381/kzg.hpp"
#ifdef ZKVM_KZG
#include "zkvm_accelerators.h"
#endif

namespace evmone::crypto {

bool kzg_verify_proof(const std::byte versioned_hash[32], const std::byte z[32],
                      const std::byte y[32], const std::byte commitment[48],
                      const std::byte proof[48]) noexcept {
    // versioned_hash must equal 0x01 || sha256(commitment)[1:].
    std::byte h[32];
    sha256(h, commitment, 48);
    h[0] = std::byte{VERSIONED_HASH_VERSION_KZG};
    if (std::memcmp(h, versioned_hash, 32) != 0)
        return false;

#ifdef ZKVM_KZG
    // EF standard C ABI: only the proof verification is delegated; the
    // versioned-hash binding above stays in the guest. All operands already use
    // the packed big-endian encoding the EF ABI expects (commitment/proof 48 B,
    // z/y 32 B), so no marshalling is needed. Note the EF argument order is
    // (commitment, z, y, proof).
    bool ok = false;
    zkvm_status st = zkvm_kzg_point_eval(
        reinterpret_cast<const zkvm_kzg_commitment*>(commitment),
        reinterpret_cast<const zkvm_kzg_field_element*>(z),
        reinterpret_cast<const zkvm_kzg_field_element*>(y),
        reinterpret_cast<const zkvm_kzg_proof*>(proof), &ok);
    return st == ZKVM_EOK && ok;
#else
    return zeg::bls::kzg_verify_core(
        reinterpret_cast<const uint8_t*>(z),
        reinterpret_cast<const uint8_t*>(y),
        reinterpret_cast<const uint8_t*>(commitment),
        reinterpret_cast<const uint8_t*>(proof));
#endif
}

}  // namespace evmone::crypto

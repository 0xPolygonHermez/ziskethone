// bls12_381_kzg.cpp — EIP-4844 KZG point-evaluation precompile (0x0a) for the
// ZisK build. Provides the one symbol evmone's point_evaluation_execute calls:
//
//   evmone::crypto::kzg_verify_proof(versioned_hash, z, y, commitment, proof)
//
// It does the versioned-hash check (0x01 || sha256(commitment)[1:]) using the
// sha256 already in the build, then delegates the proof check to the EF zkVM
// accelerator ABI (zkvm_kzg_point_eval). Replaces the failure stub in
// precompile_stubs.cpp.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <evmone_precompiles/kzg.hpp>     // declaration + VERSIONED_HASH_VERSION_KZG
#include <evmone_precompiles/sha256.hpp>  // evmone::crypto::sha256

#include "zkvm_accelerators.h"

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

    // Only the proof verification is delegated; the versioned-hash binding above
    // stays in the guest. All operands already use the packed big-endian encoding
    // the EF ABI expects (commitment/proof 48 B, z/y 32 B), so no marshalling is
    // needed, but they point into the precompile input at any alignment, and the
    // ABI types are 8-byte aligned: copy them. Note the EF argument order is
    // (commitment, z, y, proof).
    zkvm_kzg_commitment c;
    zkvm_kzg_field_element zz, yy;
    zkvm_kzg_proof p;
    std::memcpy(c.data, commitment, sizeof c.data);
    std::memcpy(zz.data, z, sizeof zz.data);
    std::memcpy(yy.data, y, sizeof yy.data);
    std::memcpy(p.data, proof, sizeof p.data);
    bool ok = false;
    const zkvm_status st = zkvm_kzg_point_eval(&c, &zz, &yy, &p, &ok);
    return st == ZKVM_EOK && ok;
}

}  // namespace evmone::crypto

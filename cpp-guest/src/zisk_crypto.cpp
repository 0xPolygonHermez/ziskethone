#include "zeg/zisk_crypto.hpp"

#include <cstring>

#include "zeg/keccak.hpp"

namespace zeg {

namespace {

// Big-endian 64-bit load.
uint64_t be_load64(const uint8_t* p) {
    return (uint64_t(p[0]) << 56) | (uint64_t(p[1]) << 48)
         | (uint64_t(p[2]) << 40) | (uint64_t(p[3]) << 32)
         | (uint64_t(p[4]) << 24) | (uint64_t(p[5]) << 16)
         | (uint64_t(p[6]) <<  8) |  uint64_t(p[7]);
}

// Convert a 32-byte BE integer to 4 native-endian 64-bit limbs in the
// little-endian-limb order that lib-c expects (limb[0] = lowest 64 bits).
void be32_to_limbs(const uint8_t* be32, uint64_t limbs[4]) {
    limbs[0] = be_load64(be32 + 24);
    limbs[1] = be_load64(be32 + 16);
    limbs[2] = be_load64(be32 +  8);
    limbs[3] = be_load64(be32 +  0);
}

// Inverse of be32_to_limbs: write 4 LE-ordered limbs as a 32-byte BE integer.
void limbs_to_be32(const uint64_t limbs[4], uint8_t* be32) {
    for (int i = 0; i < 4; ++i) {
        const uint64_t w = limbs[3 - i];   // most significant limb first
        uint8_t* q = be32 + i * 8;
        for (int j = 0; j < 8; ++j)
            q[j] = static_cast<uint8_t>(w >> (8 * (7 - j)));
    }
}

} // namespace

bool ecrecover_address(
        const evmc::bytes32&   hash,
        const evmc::uint256be& r,
        const evmc::uint256be& s,
        unsigned               recid,
        evmc::address&         out) {
    uint64_t z_limbs[4], r_limbs[4], s_limbs[4];
    be32_to_limbs(hash.bytes, z_limbs);
    be32_to_limbs(r.bytes,    r_limbs);
    be32_to_limbs(s.bytes,    s_limbs);

    uint64_t pk[8];
    if (secp256k1_ecdsa_recover(z_limbs, r_limbs, s_limbs, recid, pk) != 0) {
        return false;  // not recoverable
    }

    // pubkey limbs (x[4] || y[4]) -> 64-byte BE, then signer = keccak[12:].
    uint8_t pubkey[64];
    limbs_to_be32(pk,     pubkey);
    limbs_to_be32(pk + 4, pubkey + 32);
    const evmc::bytes32 ph = keccak256_bytes32(pubkey, 64);
    std::memcpy(out.bytes, ph.bytes + 12, 20);
    return true;
}

} // namespace zeg

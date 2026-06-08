#include "zeg/zisk_crypto.hpp"

#include <cstring>

#include "zeg/fatal.hpp"
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

constexpr uint64_t kSecp256k1N[4] = {
    0xBFD25E8CD0364141ULL,
    0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL,
    0xFFFFFFFFFFFFFFFFULL,
};

unsigned sub_256(const uint64_t a[4], const uint64_t b[4], uint64_t out[4]) {
    unsigned borrow = 0;
    for (int i = 0; i < 4; ++i) {
        const uint64_t ai = a[i];
        const uint64_t bi = b[i];
        const uint64_t di = ai - bi - borrow;
        borrow = (ai < bi + borrow) || (bi == ~uint64_t{0} && borrow) ? 1 : 0;
        out[i] = di;
    }
    return borrow;
}

bool limbs_eq(const uint64_t a[4], const uint64_t b[4]) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

} // namespace

evmc::address verify_signature_and_get_signer(
        const uint8_t*         pubkey,
        const evmc::bytes32&   signing_hash,
        const evmc::uint256be& r,
        const evmc::uint256be& s) {
    uint64_t pk[8];
    be32_to_limbs(pubkey,      pk);
    be32_to_limbs(pubkey + 32, pk + 4);

    uint64_t z_limbs[4], r_limbs[4], s_limbs[4];
    be32_to_limbs(signing_hash.bytes, z_limbs);
    be32_to_limbs(r.bytes,            r_limbs);
    be32_to_limbs(s.bytes,            s_limbs);

    uint64_t result[8];
    secp256k1_ecdsa_verify(pk, z_limbs, r_limbs, s_limbs, result);

    // result.x mod n == r (mod n). result.x < p < 2n for secp256k1,
    // so at most one conditional subtraction is needed.
    const uint64_t* rx = result;
    if (!limbs_eq(rx, r_limbs)) {
        uint64_t reduced[4];
        const unsigned borrow = sub_256(rx, kSecp256k1N, reduced);
        if (borrow != 0 || !limbs_eq(reduced, r_limbs)) {
            fatal("ECDSA signature verification failed");
        }
    }

    const evmc::bytes32 ph = keccak256_bytes32(pubkey, 64);
    evmc::address signer{};
    std::memcpy(signer.bytes, ph.bytes + 12, 20);
    return signer;
}

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

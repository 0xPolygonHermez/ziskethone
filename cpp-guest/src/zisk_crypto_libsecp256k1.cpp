// Host-build shim that exposes the ZisK `secp256k1_ecdsa_verify`
// C ABI on top of Bitcoin's libsecp256k1. Used when the real ZisK
// lib-c can't run on this host (e.g. macOS under Rosetta — no ADX).
//
// The ZisK syscall semantically computes p = u1·G + u2·PK and writes
// its (x, y) limbs to `result`; the caller then checks `result.x mod n
// == r`. libsecp256k1's public API doesn't expose that intermediate
// point, so we implement verification via the equivalent
// `ecdsa_recover` path: recover the pubkey from (z, r, s), check it
// matches the expected pubkey, then write `r` limbs straight into
// `result.x` so the caller's `result.x == r` check passes trivially.
//
// Failure path: write zeros to `result` so the caller's limb-equality
// check fails and fatals with "ECDSA signature verification failed".

#include <cstdint>
#include <cstring>

// Both `zeg/zisk_crypto.hpp` and libsecp256k1's `secp256k1.h` declare a
// symbol called `secp256k1_ecdsa_verify` — same name, different
// signature. They can't coexist in one TU. We need libsecp256k1's
// `recover_compact` + `context_create` declarations from secp256k1.h
// but NOT its `secp256k1_ecdsa_verify` (we're providing the ZisK
// flavour of that symbol ourselves). Rename it out of the way for the
// duration of the include.
#define secp256k1_ecdsa_verify _libsecp256k1_ecdsa_verify_unused
#include <secp256k1.h>
#undef  secp256k1_ecdsa_verify

namespace {

// One process-lifetime verification context. Leaks at exit, which is
// fine for a one-shot zkVM-style guest.
const secp256k1_context_t* ctx() {
    static const secp256k1_context_t* c =
        secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    return c;
}

// Limb convention from `zeg/zisk_crypto.hpp`: limb[0] is the lowest
// 64 bits, native byte order. Output is 32 bytes big-endian.
void limbs_to_be32(const uint64_t limbs[4], uint8_t be32[32]) {
    for (int word = 0; word < 4; ++word) {
        const uint64_t v = limbs[3 - word];  // most-significant word first
        for (int byte = 0; byte < 8; ++byte) {
            be32[word * 8 + byte] = static_cast<uint8_t>(v >> (56 - byte * 8));
        }
    }
}

bool try_recover(const uint8_t msg32[32], const uint8_t sig64[64],
                 int recid, uint8_t expected_pk65[65]) {
    uint8_t recovered[65];
    int     reclen = sizeof(recovered);
    if (secp256k1_ecdsa_recover_compact(ctx(), msg32, sig64,
                                        recovered, &reclen,
                                        /*compressed=*/0, recid) != 1) {
        return false;
    }
    if (reclen != 65) {
        return false;
    }
    return std::memcmp(recovered, expected_pk65, 65) == 0;
}

} // namespace

extern "C" int secp256k1_ecdsa_verify(
        const uint64_t* pk,
        const uint64_t* z,
        const uint64_t* r,
        const uint64_t* s,
        uint64_t*       result) {
    // Reconstruct the expected uncompressed pubkey (65 B = 0x04 || x || y).
    uint8_t expected_pk[65];
    expected_pk[0] = 0x04;
    limbs_to_be32(pk,     expected_pk + 1);
    limbs_to_be32(pk + 4, expected_pk + 33);

    // Build msg32 (BE) and sig64 (r_be || s_be).
    uint8_t msg32[32];
    limbs_to_be32(z, msg32);
    uint8_t sig64[64];
    limbs_to_be32(r, sig64);
    limbs_to_be32(s, sig64 + 32);

    // libsecp256k1's recover needs a recovery id (y parity bit). The
    // ZisK API doesn't carry one; try both and accept either match.
    const bool ok = try_recover(msg32, sig64, 0, expected_pk) ||
                    try_recover(msg32, sig64, 1, expected_pk);

    if (ok) {
        // The caller checks `result.x == r mod n`. Just copy `r` so
        // that check passes by construction. result.y is unused.
        std::memcpy(result, r, 4 * sizeof(uint64_t));
        std::memset(result + 4, 0, 4 * sizeof(uint64_t));
    } else {
        // Verification failed: write zeros so the caller's r-check
        // fails and it fatals with the expected error message.
        std::memset(result, 0, 8 * sizeof(uint64_t));
    }

    // Matches lib-c's "always returns 0" convention; the real signal
    // is in result.x.
    return 0;
}

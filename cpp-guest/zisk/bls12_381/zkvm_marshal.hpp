// zkvm_marshal.hpp — byte repacking between the guest's EIP-2537 BLS12-381
// encoding and the EF zkvm_accelerators.h encoding.
//
// Guest (EIP-2537): each Fp element is 64 bytes = 16 leading zero bytes + a
// 48-byte big-endian field element; coordinates are passed as separate x/y
// arrays. EF ABI: each Fp is the packed 48-byte big-endian element, points are
// packed x||y (G1) / x.c0||x.c1||y.c0||y.c1 (G2, natural order, no Fp2 swap).
//
// Marshalling is therefore purely stripping/adding the 16-byte zero pad and
// concatenating coordinates; nothing is byte-swapped. EIP-2537 requires the pad to
// be zero, and the EF ABI never sees it, so every pack_* checks it and returns
// false on a non-zero pad: the caller must then fail the precompile. Kept in a header so the
// exact same logic is exercised by the host round-trip test
// (test/zkvm_marshal_test.cpp) against the validated golden vectors.
#pragma once
#include <cstdint>
#include <cstring>

namespace zkvm_bls_marshal {

// Fp: guest [16 zero | 48 BE]  <->  EF [48 BE]. pack_fp fails on a non-zero pad.
inline bool pack_fp(const uint8_t g[64], uint8_t ef[48]) noexcept {
    uint8_t pad = 0;
    for (int i = 0; i < 16; ++i) pad |= g[i];
    std::memcpy(ef, g + 16, 48);
    return pad == 0;
}
inline void unpack_fp(const uint8_t ef[48], uint8_t g[64]) noexcept {
    std::memset(g, 0, 16);
    std::memcpy(g + 16, ef, 48);
}

// G1: EF [x48 | y48]  <->  guest x[64], y[64].
inline bool pack_g1(const uint8_t x[64], const uint8_t y[64], uint8_t ef[96]) noexcept {
    const bool okx = pack_fp(x, ef);
    const bool oky = pack_fp(y, ef + 48);
    return okx && oky;
}
inline void unpack_g1(const uint8_t ef[96], uint8_t x[64], uint8_t y[64]) noexcept {
    unpack_fp(ef, x);
    unpack_fp(ef + 48, y);
}

// G2: EF [x.c0 48 | x.c1 48 | y.c0 48 | y.c1 48]  <->  guest x[128]=(c0[64],c1[64]),
// y[128]=(c0[64],c1[64]). Natural order (no Fp2 half-swap), matching the .zisk port.
inline bool pack_g2(const uint8_t x[128], const uint8_t y[128], uint8_t ef[192]) noexcept {
    const bool ok0 = pack_fp(x, ef);
    const bool ok1 = pack_fp(x + 64, ef + 48);
    const bool ok2 = pack_fp(y, ef + 96);
    const bool ok3 = pack_fp(y + 64, ef + 144);
    return ok0 && ok1 && ok2 && ok3;
}
inline void unpack_g2(const uint8_t ef[192], uint8_t x[128], uint8_t y[128]) noexcept {
    unpack_fp(ef, x);
    unpack_fp(ef + 48, x + 64);
    unpack_fp(ef + 96, y);
    unpack_fp(ef + 144, y + 64);
}

}  // namespace zkvm_bls_marshal

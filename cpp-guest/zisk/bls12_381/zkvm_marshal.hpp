// zkvm_marshal.hpp — byte repacking between the guest's EIP-2537 BLS12-381
// encoding and the EF zkvm_accelerators.h encoding.
//
// Guest (EIP-2537): each Fp element is 64 bytes = 16 leading zero bytes + a
// 48-byte big-endian field element; coordinates are passed as separate x/y
// arrays. EF ABI: each Fp is the packed 48-byte big-endian element, points are
// packed x||y (G1) / x.c0||x.c1||y.c0||y.c1 (G2, natural order, no Fp2 swap).
//
// Marshalling is therefore purely stripping/adding the 16-byte zero pad and
// concatenating coordinates; nothing is byte-swapped. Kept in a header so the
// exact same logic is exercised by the host round-trip test
// (test/zkvm_marshal_test.cpp) against the validated golden vectors.
#pragma once
#include <cstdint>
#include <cstring>

namespace zkvm_bls_marshal {

// Fp: guest [16 zero | 48 BE]  <->  EF [48 BE].
inline void pack_fp(const uint8_t g[64], uint8_t ef[48]) noexcept { std::memcpy(ef, g + 16, 48); }
inline void unpack_fp(const uint8_t ef[48], uint8_t g[64]) noexcept {
    std::memset(g, 0, 16);
    std::memcpy(g + 16, ef, 48);
}

// G1: EF [x48 | y48]  <->  guest x[64], y[64].
inline void pack_g1(const uint8_t x[64], const uint8_t y[64], uint8_t ef[96]) noexcept {
    pack_fp(x, ef);
    pack_fp(y, ef + 48);
}
inline void unpack_g1(const uint8_t ef[96], uint8_t x[64], uint8_t y[64]) noexcept {
    unpack_fp(ef, x);
    unpack_fp(ef + 48, y);
}

// G2: EF [x.c0 48 | x.c1 48 | y.c0 48 | y.c1 48]  <->  guest x[128]=(c0[64],c1[64]),
// y[128]=(c0[64],c1[64]). Natural order (no Fp2 half-swap), matching the .zisk port.
inline void pack_g2(const uint8_t x[128], const uint8_t y[128], uint8_t ef[192]) noexcept {
    pack_fp(x, ef);
    pack_fp(x + 64, ef + 48);
    pack_fp(y, ef + 96);
    pack_fp(y + 64, ef + 144);
}
inline void unpack_g2(const uint8_t ef[192], uint8_t x[128], uint8_t y[128]) noexcept {
    unpack_fp(ef, x);
    unpack_fp(ef + 48, x + 64);
    unpack_fp(ef + 96, y);
    unpack_fp(ef + 144, y + 64);
}

}  // namespace zkvm_bls_marshal

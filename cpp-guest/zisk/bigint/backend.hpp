// backend.hpp — portable 256-bit primitives for the HOST build of zevm.
//
// Big integers are little-endian arrays of 64-bit limbs (groups of 4 = one
// "U256"). These are plain software reference versions of the multiply-add,
// modular multiply-add, add and long division that zevm's arithmetic opcodes use
// on the host. The ZisK guest does not use this file: there, the same opcodes go
// through the little-endian U256 ABI (zkvm_u256_le.h).

#pragma once

#if defined(ZEG_ZISK)
#error "bigint/backend.hpp is the host software; the ZisK guest uses zkvm_u256_le.h"
#endif

#include <cstdint>
#include <cstring>

namespace zeg::bi {

// d(512) = a*b + c, all 256-bit (4 limbs); dl = low 4, dh = high 4.
// a,b,c point to [u64;4]; dl,dh to [u64;4].

inline void arith256(const uint64_t a[4], const uint64_t b[4], const uint64_t c[4],
                     uint64_t dl[4], uint64_t dh[4]) {
    uint64_t out[8] = {0};
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned __int128 t = (unsigned __int128)a[i]*b[j] + out[i+j] + carry;
            out[i+j] = (uint64_t)t; carry = (uint64_t)(t >> 64);
        }
        out[i+4] += carry;
    }
    unsigned __int128 carry = 0;            // + c (256-bit) into the low half
    for (int i = 0; i < 8; ++i) {
        uint64_t ci = (i < 4) ? c[i] : 0;
        unsigned __int128 s = (unsigned __int128)out[i] + ci + carry;
        out[i] = (uint64_t)s; carry = s >> 64;
    }
    for (int i = 0; i < 4; ++i) { dl[i] = out[i]; dh[i] = out[i+4]; }
}

namespace detail {
// out(4) = num(8) mod m(4), bit-by-bit.
inline void mod512(const uint64_t num[8], const uint64_t m[4], uint64_t out[4]) {
    uint64_t r[8] = {0};
    auto ge = [&](const uint64_t* rr) {
        for (int i = 7; i >= 4; --i) if (rr[i]) return true;
        for (int i = 3; i >= 0; --i) { if (rr[i] > m[i]) return true; if (rr[i] < m[i]) return false; }
        return true; };
    for (int i = 511; i >= 0; --i) {
        uint64_t carry = 0;
        for (int k = 0; k < 8; ++k) { uint64_t nx = r[k] >> 63; r[k] = (r[k] << 1) | carry; carry = nx; }
        r[0] |= (num[i >> 6] >> (i & 63)) & 1ULL;
        if (ge(r)) { unsigned __int128 br = 0;
            for (int k = 0; k < 8; ++k) { uint64_t mk = k < 4 ? m[k] : 0;
                unsigned __int128 t = (unsigned __int128)r[k] - mk - br; r[k] = (uint64_t)t; br = (t >> 64) & 1; } }
    }
    for (int i = 0; i < 4; ++i) out[i] = r[i];
}
}  // namespace detail

inline void arith256_mod(const uint64_t a[4], const uint64_t b[4], const uint64_t c[4],
                         const uint64_t m[4], uint64_t d[4]) {
    uint64_t dl[4], dh[4]; arith256(a, b, c, dl, dh);
    uint64_t num[8]; for (int i = 0; i < 4; ++i) { num[i] = dl[i]; num[i+4] = dh[i]; }
    detail::mod512(num, m, d);
}

// 256-bit add a+b+cin = cout|c (software).
inline uint64_t add256(const uint64_t a[4], const uint64_t b[4], uint64_t cin, uint64_t c[4]) {
    unsigned __int128 carry = cin;
    for (int i = 0; i < 4; ++i) { unsigned __int128 s = (unsigned __int128)a[i] + b[i] + carry;
        c[i] = (uint64_t)s; carry = s >> 64; }
    return (uint64_t)carry;
}

// bigint_div (software): a = b*quo + rem, bit-by-bit long division.
inline void fcall_bigint_div(const uint64_t* a, int len_a, const uint64_t* b, int len_b,
                             uint64_t* quo, int* len_quo, uint64_t* rem, int* len_rem) {
    // r accumulates the remainder (up to len_b+1 limbs); q the quotient (len_a limbs).
    const int RW = len_b + 1, QW = len_a;
    uint64_t r[64] = {0}; uint64_t q[64] = {0};   // 64 limbs = 4096 bits, ample for EIP-7823
    auto ge_b = [&]() {                            // r >= b ?
        for (int i = RW-1; i >= len_b; --i) if (r[i]) return true;
        for (int i = len_b-1; i >= 0; --i) { if (r[i] > b[i]) return true; if (r[i] < b[i]) return false; }
        return true; };
    for (int i = len_a*64 - 1; i >= 0; --i) {
        uint64_t carry = 0;                        // r <<= 1
        for (int k = 0; k < RW; ++k) { uint64_t nx = r[k] >> 63; r[k] = (r[k] << 1) | carry; carry = nx; }
        r[0] |= (a[i>>6] >> (i&63)) & 1ULL;
        if (ge_b()) {
            unsigned __int128 br = 0;               // r -= b
            for (int k = 0; k < RW; ++k) { uint64_t bk = k < len_b ? b[k] : 0;
                unsigned __int128 t = (unsigned __int128)r[k] - bk - br; r[k] = (uint64_t)t; br = (t >> 64) & 1; }
            q[i>>6] |= 1ULL << (i&63);              // set quotient bit
        }
    }
    // Match the emulator's bigint_div: quo/rem lengths rounded up to a multiple
    // of 4 limbs (one U256 word), zero-padded; minimum 4.
    int lq = QW; while (lq > 1 && q[lq-1] == 0) --lq; lq = ((lq + 3) / 4) * 4;
    int lr = len_b; while (lr > 1 && r[lr-1] == 0) --lr; lr = ((lr + 3) / 4) * 4;
    for (int i = 0; i < lq; ++i) quo[i] = q[i];   // q is zero-initialised beyond
    for (int i = 0; i < lr; ++i) rem[i] = r[i];   // r is zero-initialised beyond
    *len_quo = lq; *len_rem = lr;
}


} // namespace zeg::bi

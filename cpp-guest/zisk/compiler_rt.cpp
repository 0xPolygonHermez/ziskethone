// compiler_rt.cpp — the libgcc / libm / libstdc++ runtime routines the guest
// references but that we cannot link from the toolchain (its libgcc/libstdc++
// are built for rv64imac — the compressed 'c' extension ZisK does not run).
//
// Provided here for rv64ima:
//   * integer builtins  __bswap{di,si}2, __clz/__ctzdi2
//   * soft-float        __divdf3, __extendsfdf2, __floatundidf, __fixunsdfdi, ceil
//                       (reached only via std::unordered_map's float load-factor /
//                        bucket math — small, non-negative, exact-integer inputs)
//   * libc              strcmp
//   * libstdc++         std::__detail::_Prime_rehash_policy::{_M_next_bkt,_M_need_rehash}
//
// The soft-float ops are full IEEE-754 binary64 implementations (not just the
// b==1.0 fast path) so they stay correct if the load factor ever changes.

#include <cstddef>
#include <cstdint>
#include <utility>
#include <unordered_map>   // declares std::__detail::_Prime_rehash_policy

#include <zeg/bswap.hpp>   // zeg::bswap64 — the shared byte-swap implementation

using u64 = uint64_t;
using u32 = uint32_t;

// ===========================================================================
// libgcc integer builtins
// ===========================================================================
extern "C" {

// libgcc ABI symbol — the compiler emits calls to it for byte-swap idioms it
// doesn't inline (it survives --gc-sections, so it is referenced). The
// implementation is the shared zeg::bswap64 (zeg/bswap.hpp); zevm uses that
// inline directly and never routes through this symbol.
u64 __bswapdi2(u64 x) { return zeg::bswap64(x); }
u32 __bswapsi2(u32 x) {
    return (x >> 24) | ((x >> 8) & 0xFF00u) | ((x << 8) & 0xFF0000u) | (x << 24);
}
int __clzdi2(u64 x) {               // x != 0 (undefined for 0, per libgcc)
    int n = 0;
    while (!(x & (1ull << 63))) { x <<= 1; ++n; }
    return n;
}
int __ctzdi2(u64 x) {               // x != 0
    int n = 0;
    while (!(x & 1)) { x >>= 1; ++n; }
    return n;
}

int strcmp(const char* a, const char* b) {
    while (*a && (*a == *b)) { ++a; ++b; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

// 128-bit unsigned divide/modulo (emitted for u128/u64 ops in crypto_sw.cpp
// and __divdf3). Restoring binary long division.
using u128 = unsigned __int128;
static u128 udivmod128(u128 n, u128 d, u128* rem) {
    if (d == 0) { volatile int z = 0; return 1 / z; }   // trap: divide by zero
    if (d > n) { if (rem) *rem = n; return 0; }
    u128 q = 0, r = 0;
    for (int i = 127; i >= 0; --i) {
        r = (r << 1) | ((n >> i) & 1);
        if (r >= d) { r -= d; q |= (u128)1 << i; }
    }
    if (rem) *rem = r;
    return q;
}
u128 __udivti3(u128 a, u128 b) { return udivmod128(a, b, nullptr); }
u128 __umodti3(u128 a, u128 b) { u128 r; udivmod128(a, b, &r); return r; }

// 128-bit variable shifts (built from 64-bit shifts so they don't recurse into
// themselves). Shift amount assumed in [0, 128).
u128 __ashlti3(u128 a, int b) {
    if (b == 0) return a;
    u64 lo = (u64)a, hi = (u64)(a >> 64);
    if (b >= 64) { hi = lo << (b - 64); lo = 0; }
    else         { hi = (hi << b) | (lo >> (64 - b)); lo <<= b; }
    return ((u128)hi << 64) | lo;
}
u128 __lshrti3(u128 a, int b) {
    if (b == 0) return a;
    u64 lo = (u64)a, hi = (u64)(a >> 64);
    if (b >= 64) { lo = hi >> (b - 64); hi = 0; }
    else         { lo = (lo >> b) | (hi << (64 - b)); hi >>= b; }
    return ((u128)hi << 64) | lo;
}

} // extern "C"

// ===========================================================================
// soft-float (binary64)
// ===========================================================================
namespace {
union D { double d; u64 u; };
union F { float  f; u32 u; };
}

extern "C" {

double __extendsfdf2(float f) {
    F in{}; in.f = f;
    u32 b = in.u;
    u64 sign = (u64)(b >> 31) << 63;
    u32 exp = (b >> 23) & 0xFF;
    u32 frac = b & 0x7FFFFF;
    D out{};
    if (exp == 0) {
        if (frac == 0) { out.u = sign; }
        else {                                   // subnormal float -> normal double
            int sh = 0;
            while (!(frac & 0x800000)) { frac <<= 1; ++sh; }
            frac &= 0x7FFFFF;
            u64 E = (u64)(1023 - 127 + 1 - sh);
            out.u = sign | (E << 52) | ((u64)frac << 29);
        }
    } else if (exp == 0xFF) {                     // inf/nan
        out.u = sign | (0x7FFull << 52) | ((u64)frac << 29);
    } else {
        u64 E = (u64)exp - 127 + 1023;
        out.u = sign | (E << 52) | ((u64)frac << 29);
    }
    return out.d;
}

double __floatundidf(u64 x) {
    if (x == 0) return 0.0;
    int e = 63;
    while (!((x >> e) & 1)) --e;                  // position of MSB
    int exp = e + 1023;
    u64 mant;
    if (e <= 52) {
        mant = x << (52 - e);
    } else {
        int sh = e - 52;
        u64 lost = x & ((1ull << sh) - 1);
        mant = x >> sh;
        u64 half = 1ull << (sh - 1);
        if (lost > half || (lost == half && (mant & 1))) {
            ++mant;
            if (mant >> 53) { mant >>= 1; ++exp; }
        }
    }
    mant &= ~(1ull << 52);                        // drop implicit leading 1
    D r{}; r.u = ((u64)exp << 52) | mant;
    return r.d;
}

u64 __fixunsdfdi(double d) {
    D v{}; v.d = d;
    u64 bits = v.u;
    if (bits >> 63) return 0;                     // negative -> 0
    int exp = (int)((bits >> 52) & 0x7FF);
    int e = exp - 1023;
    if (e < 0) return 0;
    u64 mant = (bits & ((1ull << 52) - 1)) | (1ull << 52);
    if (e >= 64) return ~0ull;
    if (e >= 52) return mant << (e - 52);
    return mant >> (52 - e);                      // truncate toward zero
}

double ceil(double d) {
    D v{}; v.d = d;
    u64 bits = v.u;
    int exp = (int)((bits >> 52) & 0x7FF);
    int e = exp - 1023;
    if (e >= 52) return d;                         // integer / inf / nan
    if (e < 0) {                                   // |d| < 1
        if ((bits << 1) == 0) return d;            // +-0
        if (bits >> 63) { v.u = 0x8000000000000000ull; return v.d; }  // (-1,0) -> -0
        return 1.0;
    }
    u64 mask = (1ull << (52 - e)) - 1;
    if ((bits & mask) == 0) return d;              // already integer
    u64 r = bits;
    if (!(bits >> 63)) r += (1ull << (52 - e));     // positive -> round up magnitude
    r &= ~mask;
    v.u = r;
    return v.d;
}

double __divdf3(double a, double b) {
    using u128 = unsigned __int128;
    D ua{}, ub{}, ur{};
    ua.d = a; ub.d = b;
    u64 A = ua.u, B = ub.u;
    int signR = (int)((A ^ B) >> 63) & 1;
    int eA = (int)((A >> 52) & 0x7FF), eB = (int)((B >> 52) & 0x7FF);
    u64 mA = A & ((1ull << 52) - 1), mB = B & ((1ull << 52) - 1);

    if (eB == 0x7FF) { ur.u = (u64)signR << 63; return ur.d; }      // a / inf = 0
    if (eB == 0 && mB == 0) {                                       // a / 0 = inf
        ur.u = ((u64)signR << 63) | (0x7FFull << 52); return ur.d;
    }
    if (eA == 0x7FF) {                                              // inf / finite = inf
        ur.u = ((u64)signR << 63) | (0x7FFull << 52); return ur.d;
    }
    if (eA == 0) {
        if (mA == 0) { ur.u = (u64)signR << 63; return ur.d; }      // 0 / x = 0
        while (!(mA & (1ull << 52))) { mA <<= 1; --eA; }            // normalize subnormal a
        ++eA;
    } else {
        mA |= (1ull << 52);
    }
    if (eB == 0) {
        while (!(mB & (1ull << 52))) { mB <<= 1; --eB; }            // normalize subnormal b
        ++eB;
    } else {
        mB |= (1ull << 52);
    }

    // mantissa quotient in (0.5, 2), scaled by 2^63.
    u128 num = (u128)mA << 63;
    u64 Q = (u64)(num / mB);
    u64 R = (u64)(num - (u128)Q * mB);
    int e = eA - eB + 1023;
    if (!(Q >> 63)) { Q <<= 1; e -= 1; }                           // ensure leading bit at 63

    u64 mant = Q >> 11;                                            // implicit bit + 52 frac
    u64 lost = Q & ((1ull << 11) - 1);
    u64 half = 1ull << 10;
    bool roundup = lost > half || (lost == half && (R != 0 || (mant & 1)));
    if (roundup) { ++mant; if (mant >> 53) { mant >>= 1; ++e; } }
    mant &= ~(1ull << 52);

    if (e <= 0)     { ur.u = (u64)signR << 63; return ur.d; }       // underflow -> 0
    if (e >= 0x7FF) { ur.u = ((u64)signR << 63) | (0x7FFull << 52); return ur.d; }
    ur.u = ((u64)signR << 63) | ((u64)e << 52) | mant;
    return ur.d;
}

} // extern "C"

// ===========================================================================
// std::unordered_map prime rehash policy. Bucket counts only affect hash
// distribution (correctness is independent), so a simple next-prime stepping
// over a fixed table + odd-number primality fallback is sufficient.
// ===========================================================================
namespace {
bool is_prime(std::size_t n) {
    if (n < 2) return false;
    if (n % 2 == 0) return n == 2;
    for (std::size_t i = 3; i * i <= n; i += 2) if (n % i == 0) return false;
    return true;
}
std::size_t next_prime(std::size_t n) {
    static const std::size_t kSmall[] = {
        2, 5, 11, 23, 47, 97, 197, 397, 797, 1597, 3203, 6421, 12853,
        25717, 51437, 102877, 205759, 411527, 823117, 1646237, 3292489,
        6584983, 13169977, 26339969, 52679969, 105359939, 210719881};
    for (std::size_t p : kSmall) if (p >= n) return p;
    std::size_t c = n | 1;
    while (!is_prime(c)) c += 2;
    return c;
}
} // namespace

namespace std::__detail {

std::size_t _Prime_rehash_policy::_M_next_bkt(std::size_t __n) const noexcept {
    const std::size_t __b = next_prime(__n < 2 ? 2 : __n);
    _M_next_resize = __b;                          // grow when element count reaches bucket count (lf<=1)
    return __b;
}

std::pair<bool, std::size_t>
_Prime_rehash_policy::_M_need_rehash(std::size_t __n_bkt, std::size_t __n_elt,
                                     std::size_t __n_ins) const noexcept {
    if (__n_elt + __n_ins > _M_next_resize) {
        std::size_t __min = __n_elt + __n_ins;     // / max_load_factor (>=1 here)
        if (__min >= __n_bkt) {
            std::size_t __want = __min + 1;
            if (__n_bkt * 2 > __want) __want = __n_bkt * 2;
            return {true, _M_next_bkt(__want)};     // updates _M_next_resize
        }
        _M_next_resize = __n_bkt;
        return {false, 0};
    }
    return {false, 0};
}

} // namespace std::__detail

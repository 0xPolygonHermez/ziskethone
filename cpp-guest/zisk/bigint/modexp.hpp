// modexp.hpp — M3 of the MODEXP port: the EIP-198 driver.
//
// Binary exponentiation (square-and-multiply) over the bigint layer, with the
// exponent bits hinted (bin_decomp) and recomposed for verification — faithful
// to zisklib/lib/bigint/modexp.rs — plus the EIP-198 byte<->limb parsing.
// modexp_compute() is the contract evmone's point precompile needs.

#pragma once

#include "bignum.hpp"

namespace zeg::bi {

inline constexpr int MEXP_MAXW = 40;     // U256 words per operand (EIP-7823 ≤32 + slack)

// ---- big-endian bytes <-> little-endian limbs --------------------------------
// → minimal u64 limbs (≥1). Returns limb count.
inline int be_to_u64(const uint8_t* bytes, int len, uint64_t* out) {
    int fnz = 0; while (fnz < len && bytes[fnz] == 0) ++fnz;
    if (fnz >= len) { out[0] = 0; return 1; }
    const uint8_t* p = bytes + fnz; int n = len - fnz;
    int nl = (n + 7) / 8; for (int i = 0; i < nl; ++i) out[i] = 0;
    for (int i = 0; i < n; ++i) out[i / 8] |= (uint64_t)p[n - 1 - i] << ((i % 8) * 8);
    return nl;
}
// → U256 words (u64 count padded to ×4). Returns word count.
inline int be_to_words(const uint8_t* bytes, int len, uint64_t* out) {
    int nl = be_to_u64(bytes, len, out);
    int padded = ((nl + 3) / 4) * 4; for (int i = nl; i < padded; ++i) out[i] = 0;
    return padded / 4;
}
// U256 words (le) → big-endian bytes into out[0..out_len], zero-filled.
inline void words_to_be(const uint64_t* w, int nwords, uint8_t* out, int out_len) {
    for (int i = 0; i < out_len; ++i) out[i] = 0;
    for (int i = 0; i < nwords * 4; ++i)
        for (int j = 0; j < 8; ++j) {
            int pos = i * 8 + j;
            if (pos < out_len) out[out_len - 1 - pos] = (uint8_t)((w[i] >> (j * 8)) & 0xFF);
        }
}

inline void wcopy(uint64_t* d, const uint64_t* s, int nwords) { for (int i = 0; i < nwords*4; ++i) d[i] = s[i]; }

// Exponent bits buffer (≤ EIP-7823 1024-byte exp = 8192 bits). Static: the inner
// rem fcalls would clobber the bin_decomp result buffer, so all bits are read up
// front (as zisklib does). Single-threaded guest ⇒ a static buffer is fine.
inline uint64_t* exp_bits_buf() { static uint64_t b[8200]; return b; }

// ---- the two exponentiation paths -------------------------------------------
// modulus 1 word. Writes result word to out[4].
inline void modexp_short(const uint64_t* base, int lb, const uint64_t* exp, int le,
                         const uint64_t m[4], uint64_t out[4]) {
    uint64_t base_mod[4]; rem_short(base, lb, m, base_mod);
    uint64_t* bits = exp_bits_buf();
    int nb = fcall_bin_decomp(exp, le, bits);
    if (!(nb > 0 && bits[0] == 1)) fail();
    uint64_t rec[MEXP_MAXW] = {0};
    rec[(nb-1) >> 6] = 1ULL << ((nb-1) & 63);
    uint64_t cur[4]; cp4(cur, base_mod);
    for (int bi = 1; bi < nb; ++bi) {
        if (is_zero4(cur)) { out[0]=out[1]=out[2]=out[3]=0; return; }
        uint64_t t[4]; square_and_reduce_short(cur, m, t); cp4(cur, t);
        if (bits[bi] == 1) {
            uint64_t u[4]; mul_and_reduce_short(cur, base_mod, m, u); cp4(cur, u);
            int pos = nb - 1 - bi; rec[pos >> 6] |= 1ULL << (pos & 63);
        }
    }
    for (int i = 0; i < le; ++i) if (rec[i] != exp[i]) fail();
    cp4(out, cur);
}
// modulus ≥ 2 words. Writes result words to out, returns word count.
inline int modexp_long(const uint64_t* base, int lb, const uint64_t* exp, int le,
                       const uint64_t* m, int lm, uint64_t* out) {
    uint64_t base_mod[MEXP_MAXW]; int lbm = rem_long(base, lb, m, lm, base_mod);
    uint64_t* bits = exp_bits_buf();
    int nb = fcall_bin_decomp(exp, le, bits);
    if (!(nb > 0 && bits[0] == 1)) fail();
    uint64_t rec[MEXP_MAXW] = {0};
    rec[(nb-1) >> 6] = 1ULL << ((nb-1) & 63);
    uint64_t cur[MEXP_MAXW]; int cl = lbm; wcopy(cur, base_mod, lbm);
    for (int bi = 1; bi < nb; ++bi) {
        if (cl == 1 && is_zero4(cur)) { out[0]=out[1]=out[2]=out[3]=0; return 1; }
        uint64_t t[MEXP_MAXW]; int tl = square_and_reduce_long(cur, cl, m, lm, t);
        wcopy(cur, t, tl); cl = tl;
        if (bits[bi] == 1) {
            uint64_t u[MEXP_MAXW]; int ul = mul_and_reduce_long(cur, cl, base_mod, lbm, m, lm, u);
            wcopy(cur, u, ul); cl = ul;
            int pos = nb - 1 - bi; rec[pos >> 6] |= 1ULL << (pos & 63);
        }
    }
    for (int i = 0; i < le; ++i) if (rec[i] != exp[i]) fail();
    wcopy(out, cur, cl); return cl;
}

// ---- public: (base^exp) mod m for big-endian byte operands -------------------
// Writes mod_len big-endian bytes to output (zero-padded). Matches EIP-198.
inline void modexp_compute(const uint8_t* base_b, int base_len, const uint8_t* exp_b, int exp_len,
                           const uint8_t* mod_b, int mod_len, uint8_t* output) {
    uint64_t base[MEXP_MAXW], mod[MEXP_MAXW], expv[2*MEXP_MAXW];
    int lb = be_to_words(base_b, base_len, base);
    int lm = be_to_words(mod_b, mod_len, mod);
    int le = be_to_u64(exp_b, exp_len, expv);     // exponent kept as raw u64 limbs

    uint64_t res[MEXP_MAXW]; int rl;
    // Edge cases (mirror zisklib modexp dispatch).
    bool mod_is_zero = (lm == 1 && is_zero4(mod));
    bool mod_is_one  = (lm == 1 && is_one4(mod));
    bool exp_is_zero = (le == 1 && expv[0] == 0);
    if (mod_is_zero || mod_is_one) { res[0]=res[1]=res[2]=res[3]=0; rl = 1; }
    else if (exp_is_zero) { res[0]=1; res[1]=res[2]=res[3]=0; rl = 1; }
    else if (lb == 1 && is_zero4(base)) { res[0]=res[1]=res[2]=res[3]=0; rl = 1; }
    else if (lb == 1 && is_one4(base)) { res[0]=1; res[1]=res[2]=res[3]=0; rl = 1; }
    else if (lm == 1) { modexp_short(base, lb, expv, le, mod, res); rl = 1; }
    else { rl = modexp_long(base, lb, expv, le, mod, lm, res); }

    words_to_be(res, rl, output, mod_len);
}

} // namespace zeg::bi

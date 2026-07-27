// Tx intrinsic gas (Yellow Paper §6.2):
//   base
//   + sum over calldata: 4 (zero byte) or 16 (non-zero, EIP-2028)
//   + EIP-3860 initcode word cost for creates
//   + EIP-2930 access-list cost: 2400/addr + 1900/storage-key
//   + EIP-7702 auth-list cost: PER_EMPTY_ACCOUNT_COST per auth
//
// Pure function over a parsed `Transactions::View`. Aborts via
// zeg::fatal on malformed typed-tx access-list RLP.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "zeg/transactions.hpp"

namespace zeg {

// Both calldata gas rules are a function of the non-zero byte count: EIP-2028
// charges 4/byte + 12 extra per non-zero, and EIP-7623's floor takes
// zero * 1 + non_zero * 4 tokens. Zbb's orc.b fills every byte of a word with
// its own OR-reduction, so cpop counts 8 bits per non-zero byte — 8 bytes per
// iteration instead of one. The prologue aligns first (ZisK charges extra for
// unaligned loads) and the tail loop doubles as the no-Zbb fallback.
inline size_t count_nonzero_bytes(std::span<const uint8_t> data) {
    const uint8_t* p = data.data();
    size_t i = 0, nz = 0;
#if defined(__riscv_zbb)
    for (; i < data.size() && (reinterpret_cast<uintptr_t>(p + i) & 7u); ++i) nz += (p[i] != 0);
    uint64_t bits = 0;  // 8 per non-zero byte
    for (; i + 8 <= data.size(); i += 8) {
        uint64_t w, m;
        __builtin_memcpy(&w, p + i, sizeof(w));
        asm("orc.b %0, %1" : "=r"(m) : "r"(w));
        bits += __builtin_popcountll(m);
    }
    nz += bits >> 3;
#endif
    for (; i < data.size(); ++i) nz += (p[i] != 0);
    return nz;
}

// `is_shanghai_or_later` gates the EIP-3860 initcode-word-cost charge
// (2 gas per 32 bytes of init code for creation txs). EIP-3860
// activates in Shanghai — pre-Shanghai EEST fixtures (Berlin/London/
// Paris) would be over-charged otherwise, producing a state-root
// divergence on every creation tx.
int64_t compute_intrinsic_gas(const Transactions::View& tx,
                              bool is_shanghai_or_later);

} // namespace zeg

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

#include <cstdint>

#include "zeg/transactions.hpp"

namespace zeg {

// `is_shanghai_or_later` gates the EIP-3860 initcode-word-cost charge
// (2 gas per 32 bytes of init code for creation txs). EIP-3860
// activates in Shanghai — pre-Shanghai EEST fixtures (Berlin/London/
// Paris) would be over-charged otherwise, producing a state-root
// divergence on every creation tx.
int64_t compute_intrinsic_gas(const Transactions::View& tx,
                              bool is_shanghai_or_later);

} // namespace zeg

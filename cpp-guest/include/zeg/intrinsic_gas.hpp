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

int64_t compute_intrinsic_gas(const Transactions::View& tx);

} // namespace zeg

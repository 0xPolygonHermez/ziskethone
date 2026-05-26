// EIP-6110 deposit-request extraction.
//
// Deposits are emitted as `DepositEvent` logs by the beacon-deposit
// contract during regular tx execution (no system call). Each event
// carries five Solidity-encoded `bytes` fields — pubkey 48,
// withdrawal_credentials 32, amount 8, signature 96, index 8 — and the
// EIP-6110 request body is those five fields concatenated in spec order
// = 192 bytes per deposit. Reverted logs are dropped from `receipts`
// upstream via the journal mechanism, so the scan can read straight
// through.

#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "zeg/receipt.hpp"

namespace zeg {

// Scan `receipts` for DepositEvent logs from the canonical beacon-
// deposit contract and append the 192-byte spec body of each deposit
// to `out`. `out` is the raw concatenation — the EIP-7685 type-byte
// prefix is the caller's responsibility.
void extract_deposit_requests(std::span<const TxReceipt> receipts,
                              std::vector<uint8_t>&      out);

} // namespace zeg

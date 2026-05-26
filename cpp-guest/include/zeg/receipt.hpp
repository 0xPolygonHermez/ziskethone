// Transaction receipts and their canonical RLP encoding (Yellow Paper
// §4.3.1):
//
//   Legacy:  rlp([status, cum_gas_used, logs_bloom, logs])
//   Typed:   type_byte || rlp([…same fields…])
//
// where each `log` is RLP-encoded as `[address, [topics…], data]`.
// `LogEntry` and `TxReceipt` are pure data structs — owned by
// `ZiskStateDB::tx_receipts_` but defined here so this header
// (and the EIP-6110 deposit-extraction module) can describe them.

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include <evmc/evmc.hpp>

#include "zeg/transactions.hpp"

namespace zeg {

// One log emission. `data` and `topics` are owned copies of the
// EVM-supplied buffers, so the originals can be freed safely.
struct LogEntry {
    evmc::address              address;
    std::vector<evmc::bytes32> topics;   // up to 4 per EVM rules
    std::vector<uint8_t>       data;
};

// One tx receipt. `tx_type`, `status`, `cumulative_gas_used`, and
// `logs_bloom` are finalized at the end of the tx; `logs` is filled
// incrementally by `emit_log` during execution (with rollback
// truncation if the EVM frame reverts).
struct TxReceipt {
    Transactions::Type       tx_type{Transactions::Type::Legacy};
    bool                     status{false};
    uint64_t                 cumulative_gas_used{0};
    std::array<uint8_t, 256> logs_bloom{};
    std::vector<LogEntry>    logs;
};

// Canonical receipt encoding per Yellow Paper §4.3.1.
std::vector<uint8_t> encode_receipt(const TxReceipt& r);

} // namespace zeg

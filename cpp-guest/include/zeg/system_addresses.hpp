// Pectra-era protocol-defined addresses, gas limits, and request-type
// bytes. Header-only — every constant is `constexpr` and used by
// `ZiskStateDB` (block-execution driver, system-call helper) plus the
// EIP-6110 deposit-extraction module.
//
// These values are fixed by EIPs (4788 / 2935 / 7002 / 7251 / 6110 /
// 7685 / 4844). Unlike `zeg/config.hpp` (user-pinned chain id), they
// can't be changed without violating consensus.

#pragma once

#include <cstdint>

#include <evmc/evmc.hpp>

namespace zeg {

// ===== System call addresses & gas =====
//
// EIP-4788 / EIP-2935 / EIP-7002 / EIP-7251 all use the same synthetic
// system caller and a 30M gas limit.

constexpr evmc::address kSystemAddress{{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe,
}};
constexpr evmc::address kBeaconRootsAddress{{
    0x00, 0x0F, 0x3d, 0xf6, 0xD7, 0x32, 0x80, 0x7E,
    0xf1, 0x31, 0x9f, 0xB7, 0xB8, 0xbB, 0x85, 0x22,
    0xd0, 0xBe, 0xac, 0x02,
}};
constexpr evmc::address kHistoryStorageAddress{{
    0x00, 0x00, 0xF9, 0x08, 0x27, 0xF1, 0xC5, 0x3a,
    0x10, 0xcb, 0x7A, 0x02, 0x33, 0x5B, 0x17, 0x53,
    0x20, 0x00, 0x29, 0x35,
}};
// EIP-7002: withdrawal-requests predeploy. Dequeues pending withdrawal
// requests when called with empty calldata. Each record is 76 bytes:
// 20 source_address || 48 validator_pubkey || 8 amount_gwei (BE).
constexpr evmc::address kWithdrawalRequestsAddress{{
    0x00, 0x00, 0x09, 0x61, 0xEf, 0x48, 0x0E, 0xb5,
    0x5e, 0x80, 0xD1, 0x9a, 0xd8, 0x35, 0x79, 0xA6,
    0x4c, 0x00, 0x70, 0x02,
}};
// EIP-7251: consolidation-requests predeploy. Same shape as 7002;
// each record is 116 bytes: 20 source_address || 48 source_pubkey ||
// 48 target_pubkey.
constexpr evmc::address kConsolidationRequestsAddress{{
    0x00, 0x00, 0xBB, 0xdD, 0xc7, 0xCE, 0x48, 0x86,
    0x42, 0xfb, 0x57, 0x9F, 0x8B, 0x00, 0xf3, 0xa5,
    0x90, 0x00, 0x72, 0x51,
}};
constexpr int64_t kSystemCallGas = 30'000'000;

// EIP-6110: deposits are extracted from event logs emitted by the
// beacon-deposit contract during regular tx execution (no system
// call). Address is the canonical mainnet value; testnets that use a
// different deposit contract will need this configurable.
constexpr evmc::address kDepositContractAddress{{
    0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40,
    0x35, 0x6c, 0xBB, 0x83, 0x9C, 0xbe, 0x05, 0x30,
    0x3d, 0x77, 0x05, 0xFa,
}};

// ===== EIP-7685 request type bytes =====

constexpr uint8_t kRequestTypeDeposit       = 0x00;
constexpr uint8_t kRequestTypeWithdrawal    = 0x01;
constexpr uint8_t kRequestTypeConsolidation = 0x02;

// ===== EIP-4844 blob-gas constants =====

constexpr uint64_t kMinBaseFeePerBlobGas      = 1;
constexpr uint64_t kBlobBaseFeeUpdateFraction = 3338477;
constexpr uint64_t kGasPerBlob                = 131072;

} // namespace zeg

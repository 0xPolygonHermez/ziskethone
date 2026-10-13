// Compile-time chain-wide constants for the ZisK Ethereum guest.
// These are pinned at build time rather than carried in the input
// stream so they can't be tampered with by the prover.

#pragma once

#include <cstdint>

namespace zeg {

// EVM chain id: Ethereum mainnet (1), or Sepolia (11155111) when built with
// ZEG_CHAIN=sepolia. Consumed by the EVM tx_context (CHAINID opcode) and by
// EIP-7702 auth validation.
#ifdef ZEG_CHAIN_SEPOLIA
constexpr uint64_t kChainId = 11155111;
#else
constexpr uint64_t kChainId = 1;
#endif

} // namespace zeg

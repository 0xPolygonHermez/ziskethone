// Compile-time chain-wide constants for the ZisK Ethereum guest.
// These are pinned at build time rather than carried in the input
// stream so they can't be tampered with by the prover.

#pragma once

#include <cstdint>

namespace zeg {

// EVM chain id. Pinned to Ethereum mainnet (1). Consumed by the EVM
// tx_context (CHAINID opcode) and by EIP-7702 auth validation.
constexpr uint64_t kChainId = 1;

} // namespace zeg

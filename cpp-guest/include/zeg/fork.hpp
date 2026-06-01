// Fork identity — a single explicit code for "which Ethereum hardfork
// this block runs under", replacing the older trick of inferring the
// fork from the header's `field_count` (number of RLP-encoded header
// fields).
//
// Why an explicit id: most forks add at least one header field, so
// `field_count` happens to identify them (15 = pre-London, 16 = London,
// 17 = Shanghai, 20 = Cancun, 21 = Prague). But Osaka (Fusaka) adds NO
// new header field over Prague — both encode 21 fields — yet it enables
// new execution semantics (EIP-7939 CLZ opcode, the P256VERIFY
// precompile, …). `field_count` therefore cannot distinguish Prague
// from Osaka. The host (input-gen) resolves the fork from the node's
// `eth_config` and stamps it here, and the guest derives BOTH the EVM
// revision and the header `field_count` from it via the tables below.
//
// The numeric values are a wire contract with rust-input-gen
// (`sections.rs`) — keep them in sync. `Unknown` (0) is what zero-filled
// or pre-fork_id inputs decode to; it resolves to Prague, the mainnet
// default, preserving the historical "field_count == 0 ⇒ Pectra"
// behaviour.

#pragma once

#include <cstdint>

#include <evmc/evmc.h>

namespace zeg {

enum class ForkId : uint64_t {
    Unknown  = 0,
    Berlin   = 1,
    London   = 2,
    Paris    = 3,
    Shanghai = 4,
    Cancun   = 5,
    Prague   = 6,
    Osaka    = 7,
};

// Number of header fields to RLP-encode for a block of this fork. Used
// by the block-header hasher (block_header.cpp).
constexpr uint32_t fork_field_count(ForkId f) noexcept {
    switch (f) {
        case ForkId::Berlin:   return 15;  // pre-London (no base_fee)
        case ForkId::London:   return 16;  // + base_fee_per_gas
        case ForkId::Paris:    return 16;  // merge: no new header field
        case ForkId::Shanghai: return 17;  // + withdrawals_root
        case ForkId::Cancun:   return 20;  // + blob_gas_used, excess_blob_gas, parent_beacon_block_root
        case ForkId::Prague:   return 21;  // + requests_hash
        case ForkId::Osaka:    return 21;  // no new header field over Prague
        case ForkId::Unknown:  return 21;  // mainnet default (Pectra)
    }
    return 21;
}

// EVM revision evmone should dispatch at for a block of this fork.
constexpr evmc_revision fork_to_revision(ForkId f) noexcept {
    switch (f) {
        case ForkId::Berlin:   return EVMC_BERLIN;
        case ForkId::London:   return EVMC_LONDON;
        case ForkId::Paris:    return EVMC_PARIS;
        case ForkId::Shanghai: return EVMC_SHANGHAI;
        case ForkId::Cancun:   return EVMC_CANCUN;
        case ForkId::Prague:   return EVMC_PRAGUE;
        case ForkId::Osaka:    return EVMC_OSAKA;
        case ForkId::Unknown:  return EVMC_PRAGUE;  // mainnet default
    }
    return EVMC_PRAGUE;
}

// Reverse map used by PreviousBlocks: ancestor records still carry the
// legacy per-record `field_count` (they're never executed, only
// re-hashed, so the EVM revision is irrelevant — only the field count
// matters for the RLP). Pick any fork with the matching field count;
// the London/Paris ambiguity at 16 is immaterial to the header RLP.
constexpr ForkId fork_from_field_count(uint32_t fc) noexcept {
    switch (fc) {
        case 15: return ForkId::Berlin;
        case 16: return ForkId::London;
        case 17: return ForkId::Shanghai;
        case 20: return ForkId::Cancun;
        case 21: return ForkId::Prague;
        case 0:  return ForkId::Prague;  // unset ⇒ mainnet default
        default: return ForkId::Prague;
    }
}

} // namespace zeg

// Compile-time fork + blob-parameter schedule for this build's chain.
//
// Audit remediation (findings #1/#2/#8): the fork and the EIP-4844/7892 blob
// parameters (TARGET/MAX_BLOB_GAS_PER_BLOCK, BLOB_BASE_FEE_UPDATE_FRACTION) are
// consensus-critical and must NOT be taken from prover-supplied input on a
// production build — a prover could present a current block under older rules
// (skipping Osaka validity checks) or inflate the blob cap. This table pins
// them at build time by `ZEG_CHAIN` (the same mechanism as kChainId and
// kDepositContractAddress) and derives them from the block's *committed*
// timestamp.
//
// It is the default source of the fork/blob parameters (so every deployed
// Sepolia/mainnet ELF is safe with no extra flag). The opt-out
// `ZEG_FORK_FROM_INPUT` makes the guest read those fields from the input
// instead; use it ONLY for the EEST conformance build, which replays every
// historical fork at synthetic activation times.
//
// Values mirror the authoritative in-repo schedule in
// rust-input-gen/src/assemble.rs (`fork_params`). Blob-gas values are blob
// counts × GAS_PER_BLOB. Keep both in sync; UPDATE at each fork / BPO change.

#pragma once

#include <cstdint>

#include "zeg/fork.hpp"

namespace zeg {

struct ForkParams {
    ForkId   fork;
    uint64_t target_blob_gas;                  // TARGET_BLOB_GAS_PER_BLOCK
    uint64_t max_blob_gas;                     // MAX_BLOB_GAS_PER_BLOCK
    uint64_t blob_base_fee_update_fraction;    // BLOB_BASE_FEE_UPDATE_FRACTION
};

namespace detail {

inline constexpr uint64_t kGasPerBlob = 131072;

struct ScheduleRow {
    uint64_t   activation;   // unix time; the row applies for timestamp >= it
    ForkParams params;
};

#if defined(ZEG_CHAIN_SEPOLIA)
// Sepolia (chain id 11155111), newest activation first.
inline constexpr ScheduleRow kForkSchedule[] = {
    {1791294816, {ForkId::Amsterdam, 14 * kGasPerBlob, 21 * kGasPerBlob, 11684671}}, // Amsterdam
    {1761607008, {ForkId::Osaka,     14 * kGasPerBlob, 21 * kGasPerBlob, 11684671}}, // BPO2
    {1761017184, {ForkId::Osaka,     10 * kGasPerBlob, 15 * kGasPerBlob,  8346193}}, // BPO1
    {1760427360, {ForkId::Osaka,      6 * kGasPerBlob,  9 * kGasPerBlob,  5007716}}, // Osaka
    {1741159776, {ForkId::Prague,     6 * kGasPerBlob,  9 * kGasPerBlob,  5007716}}, // Prague
    {1706655072, {ForkId::Cancun,     3 * kGasPerBlob,  6 * kGasPerBlob,  3338477}}, // Cancun
};
#else
// Mainnet (chain id 1), newest activation first. No Amsterdam row yet: an
// Amsterdam-timestamp block resolves to the newest *scheduled* fork (Osaka),
// so the guest never activates rules mainnet has not scheduled (finding #8).
inline constexpr ScheduleRow kForkSchedule[] = {
    {1767747671, {ForkId::Osaka,  14 * kGasPerBlob, 21 * kGasPerBlob, 11684671}}, // BPO2
    {1765290071, {ForkId::Osaka,  10 * kGasPerBlob, 15 * kGasPerBlob,  8346193}}, // BPO1
    {1764798551, {ForkId::Osaka,   6 * kGasPerBlob,  9 * kGasPerBlob,  5007716}}, // Osaka (Fusaka)
    {1746612311, {ForkId::Prague,  6 * kGasPerBlob,  9 * kGasPerBlob,  5007716}}, // Prague
    {1710338135, {ForkId::Cancun,  3 * kGasPerBlob,  6 * kGasPerBlob,  3338477}}, // Cancun
};
#endif

}  // namespace detail

// Authoritative fork + blob parameters for this build's chain at `timestamp`:
// the newest row whose activation <= timestamp. Used by the enforcing build to
// derive them from the committed block timestamp instead of trusting input.
inline ForkParams fork_params_at(uint64_t timestamp) noexcept {
    for (const auto& row : detail::kForkSchedule) {
        if (timestamp >= row.activation) {
            return row.params;
        }
    }
    // Before the earliest scheduled fork (Cancun). Unreachable on the live
    // post-Prague networks the enforcing build targets; return a pre-Cancun
    // sentinel (no blob schedule) so callers still behave deterministically.
    return ForkParams{ForkId::Unknown, 0, 0, 0};
}

}  // namespace zeg

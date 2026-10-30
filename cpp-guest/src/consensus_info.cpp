#include "zeg/consensus_info.hpp"

#include <cstring>
#include <memory>  // std::assume_aligned

#include "zeg/fatal.hpp"
#include "zeg/fork_schedule.hpp"
#include "zeg/stream.hpp"
#include "zeg/system_addresses.hpp"  // kBlobBaseFeeUpdateFraction (mainnet default)

namespace zeg {

namespace {

// Read a u64 LE from an 8-byte-aligned pointer. Same pattern as
// blocks.cpp's `u64_at` — `std::assume_aligned<8>` lets the optimiser
// lower this to a single aligned load on RISC-V.
inline uint64_t u64_at(const uint8_t* p) {
    const auto* aligned = std::assume_aligned<8>(p);
    uint64_t v;
    std::memcpy(&v, aligned, sizeof(v));
    return v;
}

} // namespace

// ============================================================================
// Withdrawal accessors
// ============================================================================

uint64_t ConsensusInfo::Withdrawal::index() const noexcept {
    return u64_at(data + kIndexOffset);
}
uint64_t ConsensusInfo::Withdrawal::validator_index() const noexcept {
    return u64_at(data + kValidatorIndexOffset);
}
const evmc::address& ConsensusInfo::Withdrawal::address() const noexcept {
    return *reinterpret_cast<const evmc::address*>(data + kAddressOffset);
}
uint64_t ConsensusInfo::Withdrawal::amount_gwei() const noexcept {
    return u64_at(data + kAmountGweiOffset);
}

// ============================================================================
// ConsensusInfo accessors
// ============================================================================

const evmc::bytes32& ConsensusInfo::parent_hash() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(header_ + kParentHashOffset);
}
const evmc::address& ConsensusInfo::beneficiary() const noexcept {
    return *reinterpret_cast<const evmc::address*>(header_ + kBeneficiaryOffset);
}
uint64_t ConsensusInfo::number   () const noexcept { return u64_at(header_ + kNumberOffset);    }
uint64_t ConsensusInfo::gas_limit() const noexcept { return u64_at(header_ + kGasLimitOffset);  }
uint64_t ConsensusInfo::timestamp() const noexcept { return u64_at(header_ + kTimestampOffset); }

ForkId ConsensusInfo::fork_id() const noexcept {
#if defined(ZEG_FORK_FROM_INPUT)
    // Opt-out (EEST conformance replays every fork at synthetic activation
    // times): take the fork from the input, resolving Unknown to Prague so
    // header checks and the EVM revision always agree.
    const auto f = static_cast<ForkId>(u64_at(header_ + kForkIdOffset));
    return f == ForkId::Unknown ? ForkId::Prague : f;
#else
    // Default (safe): derive the fork from the committed timestamp via the
    // compile-time per-chain schedule (audit #1/#8). The prover-supplied
    // kForkIdOffset field is ignored, so it cannot downgrade the fork to skip
    // newer validity rules, and a fork the chain has not scheduled (e.g.
    // Amsterdam on mainnet) is never selected.
    return fork_params_at(timestamp()).fork;
#endif
}

std::span<const uint8_t> ConsensusInfo::extra_data() const noexcept {
    const uint64_t len = u64_at(header_ + kExtraDataLenOffset);
    return std::span<const uint8_t>{header_ + kExtraDataOffset, static_cast<size_t>(len)};
}
const evmc::bytes32& ConsensusInfo::prev_randao() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(header_ + kPrevRandaoOffset);
}
const evmc::bytes32& ConsensusInfo::parent_beacon_block_root() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(header_ + kParentBeaconBlockRootOffset);
}
const evmc::uint256be& ConsensusInfo::base_fee_per_gas() const noexcept {
    return *reinterpret_cast<const evmc::uint256be*>(header_ + kBaseFeePerGasOffset);
}
uint64_t ConsensusInfo::excess_blob_gas() const noexcept {
    return u64_at(header_ + kExcessBlobGasOffset);
}
uint64_t ConsensusInfo::blob_base_fee_update_fraction() const noexcept {
#if defined(ZEG_FORK_FROM_INPUT)
    const uint64_t v = u64_at(header_ + kBlobBaseFeeUpdateFractionOffset);
    // 0 ⇒ input predates this field; default to the current-mainnet value
    // (Fusaka BPO2) so existing mainnet inputs keep decoding correctly.
    return v != 0 ? v : kBlobBaseFeeUpdateFraction;
#else
    // Default (safe): from the compile-time schedule (audit #2), never input.
    return fork_params_at(timestamp()).blob_base_fee_update_fraction;
#endif
}
uint64_t ConsensusInfo::target_blob_gas_per_block() const noexcept {
#if defined(ZEG_FORK_FROM_INPUT)
    return u64_at(header_ + kTargetBlobGasPerBlockOffset);
#else
    return fork_params_at(timestamp()).target_blob_gas;
#endif
}
uint64_t ConsensusInfo::max_blob_gas_per_block() const noexcept {
#if defined(ZEG_FORK_FROM_INPUT)
    return u64_at(header_ + kMaxBlobGasPerBlockOffset);
#else
    return fork_params_at(timestamp()).max_blob_gas;
#endif
}
const evmc::bytes32& ConsensusInfo::requests_hash() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(header_ + kRequestsHashOffset);
}
const evmc::uint256be& ConsensusInfo::difficulty() const noexcept {
    return *reinterpret_cast<const evmc::uint256be*>(header_ + kDifficultyOffset);
}
std::span<const uint8_t, 8> ConsensusInfo::nonce() const noexcept {
    return std::span<const uint8_t, 8>{header_ + kNonceOffset, 8};
}
const evmc::bytes32& ConsensusInfo::ommers_hash() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(header_ + kOmmersHashOffset);
}
uint64_t ConsensusInfo::slot_number() const noexcept {
    // EIP-7843: there is no slot number before Amsterdam. Gated on the derived
    // fork, so a pre-Amsterdam block can only ever publish slot_number 0.
    if (fork_id() < ForkId::Amsterdam) return 0;
    return u64_at(header_ + kSlotNumberOffset);
}

// ============================================================================
// Constructor — fixed 376 B prefix + N × 48 B withdrawal records.
// ============================================================================

ConsensusInfo::ConsensusInfo(const uint8_t*& cursor) {
    header_  = cursor;
    // Validate the fixed prefix is present before any u64_at(header_ + …) read
    // below (bounds check, see zeg/stream.hpp).
    advance_checked(cursor, kFixedPrefixSize);

    // Yellow-paper rule: extra_data is at most 32 bytes.
    if (u64_at(header_ + kExtraDataLenOffset) > 32) {
        fatal("ConsensusInfo: extra_data_len > 32");
    }
    if (u64_at(header_ + kForkIdOffset) > static_cast<uint64_t>(ForkId::Amsterdam)) {
        fatal("ConsensusInfo: unknown fork_id");
    }
#if !defined(ZEG_FORK_FROM_INPUT)
    // fork_id() ignores the input's fork field and derives the fork from the
    // timestamp. An honest input carries the same fork (rust-input-gen resolves
    // it from the same schedule), so a mismatch is a dishonest input or a
    // schedule that drifted between input-gen and this ELF: reject both. A
    // timestamp before the schedule (Unknown) never matches, so pre-Cancun
    // blocks are rejected instead of running as Prague.
    if (u64_at(header_ + kForkIdOffset) != static_cast<uint64_t>(fork_id())) {
        fatal("ConsensusInfo: fork_id does not match the chain's fork schedule");
    }
#endif
    // EIP-7843: slot_number enters the header only at Amsterdam. Before Amsterdam
    // it is not part of the header or the block hash, yet execution_payload_root
    // folds it into the published NPR root. An honest pre-Amsterdam input carries
    // 0 (rust-input-gen writes slot_number.unwrap_or(0)); reject a non-zero value
    // so the output stays a unique function of the block — otherwise the prover
    // could publish up to 2^64 distinct roots for one block. Gated on the derived
    // fork (audit H5: the raw field is not bound to the block). Changes no valid
    // root.
    if (fork_id() < ForkId::Amsterdam &&
        u64_at(header_ + kSlotNumberOffset) != 0) {
        fatal("ConsensusInfo: non-zero slot_number before Amsterdam");
    }

    const uint64_t n = u64_at(header_ + kWithdrawalsCountOffset);
    // Each withdrawal record is kWithdrawalRecordSize bytes; a count beyond what
    // remains is malformed — reject before the reserve and the loop.
    if (n > stream_remaining(cursor) / kWithdrawalRecordSize) {
        fatal("ConsensusInfo: withdrawals_count exceeds input size");
    }
    withdrawals_.reserve(n);
    for (uint64_t i = 0; i < n; ++i) {
        withdrawals_.push_back(Withdrawal{cursor});
        advance_checked(cursor, kWithdrawalRecordSize);
    }
}

} // namespace zeg

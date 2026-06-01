#include "zeg/consensus_info.hpp"

#include <cstring>
#include <memory>  // std::assume_aligned

#include "zeg/fatal.hpp"
#include "zeg/stream.hpp"

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

uint32_t ConsensusInfo::field_count() const noexcept {
    uint32_t v;
    std::memcpy(&v, header_ + kFieldCountOffset, sizeof(v));
    return v;
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

// ============================================================================
// Constructor — fixed 336 B prefix + N × 48 B withdrawal records.
// ============================================================================

ConsensusInfo::ConsensusInfo(const uint8_t*& cursor) {
    header_  = cursor;
    cursor  += kFixedPrefixSize;

    // Yellow-paper rule: extra_data is at most 32 bytes.
    if (u64_at(header_ + kExtraDataLenOffset) > 32) {
        fatal("ConsensusInfo: extra_data_len > 32");
    }

    const uint64_t n = u64_at(header_ + kWithdrawalsCountOffset);
    withdrawals_.reserve(n);
    for (uint64_t i = 0; i < n; ++i) {
        withdrawals_.push_back(Withdrawal{cursor});
        cursor += kWithdrawalRecordSize;
    }
}

} // namespace zeg

#include "zeg/previous_blocks.hpp"

#include <cstring>
#include <memory>  // std::assume_aligned

#include "zeg/block_header.hpp"
#include "zeg/fatal.hpp"
#include "zeg/stream.hpp"

namespace zeg {

// ============================================================================
// View accessors — each one is a typed reinterpret of a fixed offset.
// ============================================================================

namespace {

// Helper: read a u64 LE from an 8-byte-aligned offset within the record.
inline uint64_t u64_at(const uint8_t* p) {
    const auto* aligned = std::assume_aligned<8>(p);
    uint64_t v;
    std::memcpy(&v, aligned, sizeof(v));
    return v;
}

} // namespace

const evmc::bytes32& PreviousBlocks::View::parent_hash() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(data + kParentHashOffset);
}
const evmc::bytes32& PreviousBlocks::View::ommers_hash() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(data + kOmmersHashOffset);
}
const evmc::bytes32& PreviousBlocks::View::state_root() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(data + kStateRootOffset);
}
const evmc::bytes32& PreviousBlocks::View::transactions_root() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(data + kTransactionsRootOffset);
}
const evmc::bytes32& PreviousBlocks::View::receipts_root() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(data + kReceiptsRootOffset);
}
const evmc::bytes32& PreviousBlocks::View::prev_randao() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(data + kPrevRandaoOffset);
}
const evmc::bytes32& PreviousBlocks::View::withdrawals_root() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(data + kWithdrawalsRootOffset);
}
const evmc::bytes32& PreviousBlocks::View::parent_beacon_block_root() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(data + kParentBeaconBlockRootOffset);
}
const evmc::bytes32& PreviousBlocks::View::requests_hash() const noexcept {
    return *reinterpret_cast<const evmc::bytes32*>(data + kRequestsHashOffset);
}

const evmc::address& PreviousBlocks::View::coinbase() const noexcept {
    return *reinterpret_cast<const evmc::address*>(data + kCoinbaseOffset);
}

std::span<const uint8_t, 256> PreviousBlocks::View::logs_bloom() const noexcept {
    return std::span<const uint8_t, 256>{data + kLogsBloomOffset, 256};
}

std::span<const uint8_t, 8> PreviousBlocks::View::nonce() const noexcept {
    return std::span<const uint8_t, 8>{data + kNonceOffset, 8};
}

const evmc::uint256be& PreviousBlocks::View::difficulty() const noexcept {
    return *reinterpret_cast<const evmc::uint256be*>(data + kDifficultyOffset);
}
const evmc::uint256be& PreviousBlocks::View::base_fee_per_gas() const noexcept {
    return *reinterpret_cast<const evmc::uint256be*>(data + kBaseFeePerGasOffset);
}

uint64_t PreviousBlocks::View::number         () const noexcept { return u64_at(data + kNumberOffset);         }
uint64_t PreviousBlocks::View::gas_limit      () const noexcept { return u64_at(data + kGasLimitOffset);       }
uint64_t PreviousBlocks::View::gas_used       () const noexcept { return u64_at(data + kGasUsedOffset);        }
uint64_t PreviousBlocks::View::timestamp      () const noexcept { return u64_at(data + kTimestampOffset);      }
uint64_t PreviousBlocks::View::blob_gas_used  () const noexcept { return u64_at(data + kBlobGasUsedOffset);    }
uint64_t PreviousBlocks::View::excess_blob_gas() const noexcept { return u64_at(data + kExcessBlobGasOffset);  }

std::span<const uint8_t> PreviousBlocks::View::extra_data() const noexcept {
    const uint64_t len = u64_at(data + kExtraDataLenOffset);
    return std::span<const uint8_t>{data + kExtraDataOffset, static_cast<size_t>(len)};
}

// ============================================================================
// Hash computation — delegate to the shared block_header helper so the
// current-block hash path uses the exact same encoding.
// ============================================================================

namespace {

evmc::bytes32 compute_header_hash(const PreviousBlocks::View& v) {
    return compute_block_header_hash(BlockHeader{
        .parent_hash              = v.parent_hash(),
        .ommers_hash              = v.ommers_hash(),
        .coinbase                 = v.coinbase(),
        .state_root               = v.state_root(),
        .transactions_root        = v.transactions_root(),
        .receipts_root            = v.receipts_root(),
        .logs_bloom               = v.logs_bloom(),
        .difficulty               = v.difficulty(),
        .number                   = v.number(),
        .gas_limit                = v.gas_limit(),
        .gas_used                 = v.gas_used(),
        .timestamp                = v.timestamp(),
        .extra_data               = v.extra_data(),
        .prev_randao              = v.prev_randao(),
        .nonce                    = v.nonce(),
        .base_fee_per_gas         = v.base_fee_per_gas(),
        .withdrawals_root         = v.withdrawals_root(),
        .blob_gas_used            = v.blob_gas_used(),
        .excess_blob_gas          = v.excess_blob_gas(),
        .parent_beacon_block_root = v.parent_beacon_block_root(),
        .requests_hash            = v.requests_hash(),
    });
}

} // namespace

// ============================================================================
// Constructor — parse + recompute hashes + verify chain.
// ============================================================================

PreviousBlocks::PreviousBlocks(const uint8_t*& cursor) {
    const uint64_t count   = read_u64_le(cursor);
    const uint8_t* records = cursor;

    views_.reserve(count);
    hashes_.reserve(count);

    for (uint64_t i = 0; i < count; ++i) {
        views_.push_back(View{records + i * kRecordSize});
        hashes_.push_back(compute_header_hash(views_.back()));
    }
    cursor += count * kRecordSize;

    // Chain check: each block's parent_hash must equal its parent's
    // recomputed hash. The deepest ancestor's parent_hash is not
    // verified (we have no block beyond it). The link from
    // hash(block[0]) to the current block's parent_hash is checked
    // outside this class, against `ConsensusInfo::parent_hash()`.
    for (size_t i = 0; i + 1 < views_.size(); ++i) {
        if (views_[i].parent_hash() != hashes_[i + 1]) {
            fatal("PreviousBlocks: parent_hash chain mismatch");
        }
    }
}

} // namespace zeg

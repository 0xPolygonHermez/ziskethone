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

uint32_t PreviousBlocks::View::field_count() const noexcept {
    uint32_t v;
    std::memcpy(&v, data + kFieldCountOffset, sizeof(v));
    return v;
}

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
    // Ancestor records still carry the legacy per-record `field_count`
    // (they are only re-hashed, never executed, so the EVM revision is
    // irrelevant — only the field count matters for the RLP). Map it to
    // a fork so the shared header encoder can derive the count back. 0 ==
    // unset (old manifests) → Prague (Pectra default), as mainnet wants.
    const ForkId fork = fork_from_field_count(v.field_count());
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
        .fork_id                  = fork,
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

    // Linkage check — SPARSE-tolerant. The ancestor set carries only the
    // blocks the witness referenced for BLOCKHASH, so it may have gaps
    // (e.g. {parent, N-100}). We therefore verify parent_hash linkage ONLY
    // between records that are consecutive BY NUMBER (child.number ==
    // next.number + 1); a gap is legitimate and is not an error. Records
    // are ordered descending by number (index 0 = parent), so a genuine
    // adjacency shows up as a 1-step decrement between neighbours.
    //
    // The link from hash(block[0]) to the current block's parent_hash is
    // checked outside this class, against `ConsensusInfo::parent_hash()`.
    for (size_t i = 0; i + 1 < views_.size(); ++i) {
        const uint64_t child_num = views_[i].number();
        const uint64_t next_num  = views_[i + 1].number();
        if (child_num == next_num + 1 &&
            views_[i].parent_hash() != hashes_[i + 1]) {
            fatal("PreviousBlocks: parent_hash chain mismatch");
        }
    }
}

const evmc::bytes32* PreviousBlocks::hash_of_number(uint64_t number) const noexcept {
    // Linear scan by block number. The ancestor set is tiny (≤256, and in
    // practice 1 — just the parent), and the BLOCKHASH depth guard already
    // bounds callers to [1,256], so a scan is cheaper than an unordered_map
    // (which on the bare-metal ZisK target drags in the soft-float load-factor
    // runtime — no FP support here). First match wins; index 0 = parent.
    for (size_t i = 0; i < views_.size(); ++i) {
        if (views_[i].number() == number) {
            return &hashes_[i];
        }
    }
    return nullptr;
}

} // namespace zeg

// PreviousBlocks — the parent of the current block plus its earlier
// ancestors. The current block being computed is NOT in this list —
// its consensus inputs are on `ConsensusInfo`, and its derived roots /
// hash come from execution.
//
// Indexing:
//   block[0] = parent      (the previous block)
//   block[1] = grandparent
//   block[i] = the i-th ancestor of the current block
//
// Each block is a fixed-size field-by-field record in the input stream;
// the constructor parses them, recomputes each block's hash from
// canonical Pectra-era RLP, and verifies that every
// block[i].parent_hash equals hash(block[i+1]). The link from
// hash(block[0]) to the current block's parent_hash is checked outside
// this class (in main.cpp, against `ConsensusInfo::parent_hash()`).
//
// The collection may legitimately be empty — e.g. a stateless run that
// has no need to reach any ancestor block. Callers must handle the
// `size() == 0` case (the anchor check above is then skipped).

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg {

class PreviousBlocks {
public:
    // Wire-format record size in bytes. Documented in `View` below.
    static constexpr uint64_t kRecordSize = 728;

    // Zero-copy view of one wire-format record. Fields stored as fixed
    // bytes in the stream return references; the u64 fields are read
    // via `std::assume_aligned<8> + memcpy` (same pattern as
    // Accounts::View). `extra_data()` returns a span over only the
    // valid prefix of the 32-byte extra_data buffer.
    struct View {
        const uint8_t* data;

        // Fixed offsets, all 8-byte aligned by construction.
        static constexpr size_t kParentHashOffset            = 0;
        static constexpr size_t kOmmersHashOffset            = 32;
        static constexpr size_t kCoinbaseOffset              = 64;   // 20 B + 4 B pad
        static constexpr size_t kStateRootOffset             = 88;
        static constexpr size_t kTransactionsRootOffset      = 120;
        static constexpr size_t kReceiptsRootOffset          = 152;
        static constexpr size_t kLogsBloomOffset             = 184;  // 256 B
        static constexpr size_t kDifficultyOffset            = 440;  // uint256be
        static constexpr size_t kNumberOffset                = 472;  // u64
        static constexpr size_t kGasLimitOffset              = 480;
        static constexpr size_t kGasUsedOffset               = 488;
        static constexpr size_t kTimestampOffset             = 496;
        static constexpr size_t kExtraDataLenOffset          = 504;  // u64
        static constexpr size_t kExtraDataOffset             = 512;  // 32 B buffer
        static constexpr size_t kPrevRandaoOffset            = 544;  // bytes32
        static constexpr size_t kNonceOffset                 = 576;  // 8 raw bytes
        static constexpr size_t kBaseFeePerGasOffset         = 584;  // uint256be
        static constexpr size_t kWithdrawalsRootOffset       = 616;
        static constexpr size_t kBlobGasUsedOffset           = 648;
        static constexpr size_t kExcessBlobGasOffset         = 656;
        static constexpr size_t kParentBeaconBlockRootOffset = 664;
        static constexpr size_t kRequestsHashOffset          = 696;
        // End of record: 728 (divisible by 8).

        // Hash accessors.
        const evmc::bytes32& parent_hash             () const noexcept;
        const evmc::bytes32& ommers_hash             () const noexcept;
        const evmc::bytes32& state_root              () const noexcept;
        const evmc::bytes32& transactions_root       () const noexcept;
        const evmc::bytes32& receipts_root           () const noexcept;
        const evmc::bytes32& prev_randao             () const noexcept;
        const evmc::bytes32& withdrawals_root        () const noexcept;
        const evmc::bytes32& parent_beacon_block_root() const noexcept;
        const evmc::bytes32& requests_hash           () const noexcept;

        // 20-byte miner / fee recipient.
        const evmc::address& coinbase() const noexcept;

        // 256-byte Bloom filter.
        std::span<const uint8_t, 256> logs_bloom() const noexcept;

        // 8-byte nonce (Ethereum encodes it as a fixed-width bytestring,
        // not a trimmed integer, so we return raw bytes).
        std::span<const uint8_t, 8> nonce() const noexcept;

        // uint256be slots.
        const evmc::uint256be& difficulty       () const noexcept;
        const evmc::uint256be& base_fee_per_gas () const noexcept;

        // u64 counters / metadata.
        uint64_t number         () const noexcept;
        uint64_t gas_limit      () const noexcept;
        uint64_t gas_used       () const noexcept;
        uint64_t timestamp      () const noexcept;
        uint64_t blob_gas_used  () const noexcept;
        uint64_t excess_blob_gas() const noexcept;

        // Variable-length extra_data, ≤ 32 bytes; the wire format
        // reserves a fixed 32-byte buffer and an 8-byte length prefix.
        std::span<const uint8_t> extra_data() const noexcept;
    };

    // Parse `u64 count` followed by `count` × 728-byte records, compute
    // each header's keccak hash, and verify the full parent-hash chain.
    // Aborts via zeg::fatal on chain mismatch.
    explicit PreviousBlocks(const uint8_t*& cursor);

    size_t size () const noexcept { return views_.size(); }
    bool   empty() const noexcept { return views_.empty(); }

    // Block 0 = parent (previous block); block i = i-th ancestor of the
    // current block.
    const View&          at  (size_t idx) const { return views_[idx]; }
    const evmc::bytes32& hash(size_t idx) const { return hashes_[idx]; }

private:
    std::vector<View>          views_;
    std::vector<evmc::bytes32> hashes_;
};

} // namespace zeg

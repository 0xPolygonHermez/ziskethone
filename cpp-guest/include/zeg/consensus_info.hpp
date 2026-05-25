// ConsensusInfo — per-block consensus-layer inputs the guest needs to
// execute and validate the current block.
//
// Distinct from `PreviousBlocks` (which holds the parent + earlier
// ancestor headers used by EIP-2935 / BLOCKHASH). This is a narrower,
// standalone section covering the current block's consensus inputs +
// the withdrawals list — neither is part of `PreviousBlocks`.
//
// Layout in the input stream:
//
//   uint8[200] fixed_header_prefix     // see kFieldOffset constants
//   Withdrawal × withdrawals_count     // each 48 B (= multiple of 8)
//
// No per-record trailing padding is needed — every field is naturally
// 8-byte aligned, and 48 is a multiple of 8.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg {

class ConsensusInfo {
public:
    static constexpr uint64_t kFixedPrefixSize      = 240;
    static constexpr uint64_t kWithdrawalRecordSize = 48;

    // Fixed offsets within the 240-byte header prefix. All 8-byte
    // aligned by construction.
    static constexpr size_t kParentHashOffset            = 0;    // bytes32
    static constexpr size_t kBeneficiaryOffset           = 32;   // 20 B + 4 B pad
    static constexpr size_t kNumberOffset                = 56;   // u64
    static constexpr size_t kGasLimitOffset              = 64;   // u64
    static constexpr size_t kTimestampOffset             = 72;   // u64
    static constexpr size_t kChainIdOffset               = 80;   // u64
    static constexpr size_t kExtraDataLenOffset          = 88;   // u64; <= 32
    static constexpr size_t kExtraDataOffset             = 96;   // 32 B buffer
    static constexpr size_t kPrevRandaoOffset            = 128;  // bytes32
    static constexpr size_t kParentBeaconBlockRootOffset = 160;  // bytes32
    static constexpr size_t kBaseFeePerGasOffset         = 192;  // uint256be
    static constexpr size_t kWithdrawalsCountOffset      = 224;  // u64
    static constexpr size_t kExcessBlobGasOffset         = 232;  // u64 (EIP-4844)
    // End of fixed prefix: 240.

    // Zero-copy view over one 48-byte withdrawal record (EIP-4895).
    //
    // Per-record layout:
    //   0   u64  index
    //   8   u64  validator_index
    //   16  20 B address + 4 B pad
    //   40  u64  amount (gwei)
    struct Withdrawal {
        const uint8_t* data;

        static constexpr size_t kIndexOffset          = 0;
        static constexpr size_t kValidatorIndexOffset = 8;
        static constexpr size_t kAddressOffset        = 16;
        static constexpr size_t kAmountGweiOffset     = 40;

        uint64_t             index          () const noexcept;
        uint64_t             validator_index() const noexcept;
        const evmc::address& address        () const noexcept;
        uint64_t             amount_gwei    () const noexcept;
    };

    // Parse the fixed prefix + `withdrawals_count` × 48-byte records.
    // `cursor` is advanced past every byte consumed.
    explicit ConsensusInfo(const uint8_t*& cursor);

    // ----- header accessors (zero-copy refs into the 200 B prefix) -----
    const evmc::bytes32&     parent_hash             () const noexcept;
    const evmc::address&     beneficiary             () const noexcept;
    uint64_t                 number                  () const noexcept;
    uint64_t                 gas_limit               () const noexcept;
    uint64_t                 timestamp               () const noexcept;
    uint64_t                 chain_id                () const noexcept;
    std::span<const uint8_t> extra_data              () const noexcept;
    const evmc::bytes32&     prev_randao             () const noexcept;
    const evmc::bytes32&     parent_beacon_block_root() const noexcept;
    const evmc::uint256be&   base_fee_per_gas        () const noexcept;
    uint64_t                 excess_blob_gas         () const noexcept;

    // ----- withdrawals -----
    size_t                      withdrawals_count() const noexcept { return withdrawals_.size(); }
    const Withdrawal&           withdrawal(size_t i) const         { return withdrawals_[i]; }
    std::span<const Withdrawal> withdrawals() const noexcept        { return withdrawals_; }

private:
    const uint8_t*          header_{};
    std::vector<Withdrawal> withdrawals_;
};

} // namespace zeg

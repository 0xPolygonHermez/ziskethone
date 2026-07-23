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
//   uint8[264] fixed_header_prefix     // see kFieldOffset constants
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

#include "zeg/fork.hpp"

namespace zeg {

class ConsensusInfo {
public:
    static constexpr uint64_t kFixedPrefixSize      = 368;
    static constexpr uint64_t kWithdrawalRecordSize = 48;

    // Fixed offsets within the 344-byte header prefix. All 8-byte
    // aligned by construction.
    static constexpr size_t kParentHashOffset            = 0;    // bytes32
    static constexpr size_t kBeneficiaryOffset           = 32;   // 20 B
    // 52..56 is reserved padding (it used to hold a u32 `field_count`;
    // the fork is now carried by `kForkIdOffset` as a 64-bit value, per
    // the wire contract documented in zeg/fork.hpp).
    static constexpr size_t kNumberOffset                = 56;   // u64
    static constexpr size_t kGasLimitOffset              = 64;   // u64
    static constexpr size_t kTimestampOffset             = 72;   // u64
    static constexpr size_t kExtraDataLenOffset          = 80;   // u64; <= 32
    static constexpr size_t kExtraDataOffset             = 88;   // 32 B buffer
    static constexpr size_t kPrevRandaoOffset            = 120;  // bytes32
    static constexpr size_t kParentBeaconBlockRootOffset = 152;  // bytes32
    static constexpr size_t kBaseFeePerGasOffset         = 184;  // uint256be
    static constexpr size_t kWithdrawalsCountOffset      = 216;  // u64
    static constexpr size_t kExcessBlobGasOffset         = 224;  // u64 (EIP-4844)
    static constexpr size_t kRequestsHashOffset          = 232;  // bytes32 (EIP-7685)
    // Pre-Merge consensus fields. Post-Merge these are constants
    // (difficulty=0, nonce=0x00...00, ommers_hash=kEmptyOmmersHash),
    // but reth/EEST still includes them in the header RLP. We carry
    // them in the wire format so cpp-guest can replay pre-Paris EEST
    // fixtures (Berlin, London — difficulty is a real PoW value,
    // hash mismatch otherwise).
    static constexpr size_t kDifficultyOffset            = 264;  // uint256be
    static constexpr size_t kNonceOffset                 = 296;  // 8 B
    static constexpr size_t kOmmersHashOffset            = 304;  // bytes32
    // Fork identity (see zeg/fork.hpp). 64-bit value appended at the end
    // of the prefix — distinguishes Osaka from Prague, which share the
    // same header field count. 0 (= zero-filled / pre-fork_id inputs)
    // decodes to ForkId::Unknown ⇒ Prague (mainnet default).
    static constexpr size_t kForkIdOffset                = 336;  // u64-le
    // EIP-4844/7691/7892 blob base-fee update fraction (BLOB_BASE_FEE_
    // UPDATE_FRACTION), per the block's blob schedule. Carried per-block
    // because mainnet-Osaka and EEST-Osaka share fork_id yet use different
    // schedules (mainnet evolves it at each BPO fork). 0 = pre-field input
    // ⇒ guest falls back to the current-mainnet default.
    static constexpr size_t kBlobBaseFeeUpdateFractionOffset = 344;  // u64-le
    // EIP-4844/7691/7892 TARGET_BLOB_GAS_PER_BLOCK (target blob count ×
    // GAS_PER_BLOB), per the block's blob schedule — sibling of
    // kBlobBaseFeeUpdateFractionOffset above, carried per-block for the
    // same reason (mainnet evolves it at each BPO fork; EEST forks use
    // their own canonical schedule). Used to independently re-derive
    // excess_blob_gas from the parent block and reject a header whose
    // claimed value doesn't match (EIP-4844 validity — see run.cpp).
    static constexpr size_t kTargetBlobGasPerBlockOffset = 352;  // u64-le
    // EIP-4844/7691/7892 MAX_BLOB_GAS_PER_BLOCK (max blob count ×
    // GAS_PER_BLOB) — sibling of kTargetBlobGasPerBlockOffset above, same
    // per-block-schedule reason. Needed (alongside the target) for the
    // EIP-7918 (Osaka+) reserve-price branch of the excess_blob_gas
    // formula: parent.excess_blob_gas + parent.blob_gas_used *
    // (max - target) / max — see run.cpp.
    static constexpr size_t kMaxBlobGasPerBlockOffset    = 360;  // u64-le
    // End of fixed prefix: 368.

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

    // ----- header accessors (zero-copy refs into the 232 B prefix) -----
    const evmc::bytes32&     parent_hash             () const noexcept;
    const evmc::address&     beneficiary             () const noexcept;
    uint64_t                 number                  () const noexcept;
    uint64_t                 gas_limit               () const noexcept;
    uint64_t                 timestamp               () const noexcept;
    std::span<const uint8_t> extra_data              () const noexcept;
    const evmc::bytes32&     prev_randao             () const noexcept;
    const evmc::bytes32&     parent_beacon_block_root() const noexcept;
    const evmc::uint256be&   base_fee_per_gas        () const noexcept;
    uint64_t                 excess_blob_gas         () const noexcept;
    // BLOB_BASE_FEE_UPDATE_FRACTION for this block's blob schedule. Falls
    // back to the current-mainnet value when the wire field is 0 (older
    // inputs that predate it).
    uint64_t                 blob_base_fee_update_fraction() const noexcept;
    // TARGET_BLOB_GAS_PER_BLOCK for this block's blob schedule (0 for
    // pre-Cancun inputs / inputs that predate this field — callers must
    // gate any use of it on Cancun-or-later, there is no mainnet-default
    // fallback here unlike blob_base_fee_update_fraction: silently
    // substituting a guessed schedule would turn a consensus-critical
    // accept/reject check into an unsound one).
    uint64_t                 target_blob_gas_per_block() const noexcept;
    // MAX_BLOB_GAS_PER_BLOCK for this block's blob schedule — see
    // kMaxBlobGasPerBlockOffset. Same no-fallback caveat as
    // target_blob_gas_per_block above.
    uint64_t                 max_blob_gas_per_block  () const noexcept;
    const evmc::bytes32&     requests_hash           () const noexcept;
    const evmc::uint256be&   difficulty              () const noexcept;
    std::span<const uint8_t, 8> nonce                () const noexcept;
    const evmc::bytes32&     ommers_hash             () const noexcept;
    // The hardfork this block runs under. Callers derive both the EVM
    // revision and the header field-count from it (see zeg/fork.hpp).
    // ForkId::Unknown (0 = zero-filled / pre-fork_id inputs) resolves to
    // Prague, which is correct for mainnet replays.
    ForkId                   fork_id                 () const noexcept;

    // ----- withdrawals -----
    size_t                      withdrawals_count() const noexcept { return withdrawals_.size(); }
    const Withdrawal&           withdrawal(size_t i) const         { return withdrawals_[i]; }
    std::span<const Withdrawal> withdrawals() const noexcept        { return withdrawals_; }

private:
    const uint8_t*          header_{};
    std::vector<Withdrawal> withdrawals_;
};

} // namespace zeg

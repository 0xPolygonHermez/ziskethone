#include "zeg/previous_blocks.hpp"

#include <cstring>
#include <memory>  // std::assume_aligned

#include "zeg/fatal.hpp"
#include "zeg/keccak.hpp"
#include "zeg/rlp.hpp"
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
// Hash computation — canonical Pectra-era header RLP, then keccak256.
// ============================================================================

namespace {

// Build the RLP encoding of a Pectra block header. Field order MUST
// match the Yellow Paper (App. L) — any reorder produces a wrong hash.
rlp::Bytes encode_header_rlp(const PreviousBlocks::View& v) {
    using rlp::BytesView;

    // Hashes / address / bloom / nonce / extra_data → byte-string RLP.
    const auto parent_hash_rlp        = rlp::encode(BytesView{v.parent_hash().bytes,
                                                              sizeof(v.parent_hash().bytes)});
    const auto ommers_hash_rlp        = rlp::encode(BytesView{v.ommers_hash().bytes,
                                                              sizeof(v.ommers_hash().bytes)});
    const auto coinbase_rlp           = rlp::encode(BytesView{v.coinbase().bytes,
                                                              sizeof(v.coinbase().bytes)});
    const auto state_root_rlp         = rlp::encode(BytesView{v.state_root().bytes,
                                                              sizeof(v.state_root().bytes)});
    const auto txs_root_rlp           = rlp::encode(BytesView{v.transactions_root().bytes,
                                                              sizeof(v.transactions_root().bytes)});
    const auto receipts_root_rlp      = rlp::encode(BytesView{v.receipts_root().bytes,
                                                              sizeof(v.receipts_root().bytes)});
    const auto logs_bloom_span        = v.logs_bloom();
    const auto logs_bloom_rlp         = rlp::encode(BytesView{logs_bloom_span.data(),
                                                              logs_bloom_span.size()});

    // Integers (difficulty, baseFee, u64 counters) → trimmed integer RLP.
    const auto difficulty_rlp         = rlp::encode_u256(v.difficulty());
    const auto number_rlp             = rlp::encode_u64 (v.number());
    const auto gas_limit_rlp          = rlp::encode_u64 (v.gas_limit());
    const auto gas_used_rlp           = rlp::encode_u64 (v.gas_used());
    const auto timestamp_rlp          = rlp::encode_u64 (v.timestamp());

    // extra_data (≤ 32 B) → byte-string RLP over its actual length.
    const auto extra_data_span        = v.extra_data();
    const auto extra_data_rlp         = rlp::encode(BytesView{extra_data_span.data(),
                                                              extra_data_span.size()});

    const auto prev_randao_rlp        = rlp::encode(BytesView{v.prev_randao().bytes,
                                                              sizeof(v.prev_randao().bytes)});

    // nonce — Ethereum encodes it as an 8-byte FIXED-WIDTH bytestring,
    // not as a trimmed integer. encode() handles the fixed-width path.
    const auto nonce_span             = v.nonce();
    const auto nonce_rlp              = rlp::encode(BytesView{nonce_span.data(),
                                                              nonce_span.size()});

    const auto base_fee_rlp           = rlp::encode_u256(v.base_fee_per_gas());
    const auto withdrawals_root_rlp   = rlp::encode(BytesView{v.withdrawals_root().bytes,
                                                              sizeof(v.withdrawals_root().bytes)});
    const auto blob_gas_used_rlp      = rlp::encode_u64(v.blob_gas_used());
    const auto excess_blob_gas_rlp    = rlp::encode_u64(v.excess_blob_gas());
    const auto parent_beacon_root_rlp = rlp::encode(BytesView{v.parent_beacon_block_root().bytes,
                                                              sizeof(v.parent_beacon_block_root().bytes)});
    const auto requests_hash_rlp      = rlp::encode(BytesView{v.requests_hash().bytes,
                                                              sizeof(v.requests_hash().bytes)});

    return rlp::encode_list({
        parent_hash_rlp,
        ommers_hash_rlp,
        coinbase_rlp,
        state_root_rlp,
        txs_root_rlp,
        receipts_root_rlp,
        logs_bloom_rlp,
        difficulty_rlp,
        number_rlp,
        gas_limit_rlp,
        gas_used_rlp,
        timestamp_rlp,
        extra_data_rlp,
        prev_randao_rlp,
        nonce_rlp,
        base_fee_rlp,
        withdrawals_root_rlp,
        blob_gas_used_rlp,
        excess_blob_gas_rlp,
        parent_beacon_root_rlp,
        requests_hash_rlp,
    });
}

evmc::bytes32 compute_header_hash(const PreviousBlocks::View& v) {
    const auto rlp_bytes = encode_header_rlp(v);
    return keccak256_bytes32(rlp_bytes.data(), rlp_bytes.size());
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

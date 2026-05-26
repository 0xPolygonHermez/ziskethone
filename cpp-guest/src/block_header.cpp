#include "zeg/block_header.hpp"

#include "zeg/keccak.hpp"
#include "zeg/rlp.hpp"

namespace zeg {

namespace {

// Build the RLP encoding of a Pectra block header. Field order MUST
// match the Yellow Paper (App. L) — any reorder produces a wrong hash.
rlp::Bytes encode_block_header_rlp(const BlockHeader& h) {
    using rlp::BytesView;

    // Hashes / address / bloom / nonce / extra_data → byte-string RLP.
    const auto parent_hash_rlp        = rlp::encode(BytesView{h.parent_hash.bytes,
                                                              sizeof(h.parent_hash.bytes)});
    const auto ommers_hash_rlp        = rlp::encode(BytesView{h.ommers_hash.bytes,
                                                              sizeof(h.ommers_hash.bytes)});
    const auto coinbase_rlp           = rlp::encode(BytesView{h.coinbase.bytes,
                                                              sizeof(h.coinbase.bytes)});
    const auto state_root_rlp         = rlp::encode(BytesView{h.state_root.bytes,
                                                              sizeof(h.state_root.bytes)});
    const auto txs_root_rlp           = rlp::encode(BytesView{h.transactions_root.bytes,
                                                              sizeof(h.transactions_root.bytes)});
    const auto receipts_root_rlp      = rlp::encode(BytesView{h.receipts_root.bytes,
                                                              sizeof(h.receipts_root.bytes)});
    const auto logs_bloom_rlp         = rlp::encode(BytesView{h.logs_bloom.data(),
                                                              h.logs_bloom.size()});

    // Integers (difficulty, baseFee, u64 counters) → trimmed integer RLP.
    const auto difficulty_rlp         = rlp::encode_u256(h.difficulty);
    const auto number_rlp             = rlp::encode_u64 (h.number);
    const auto gas_limit_rlp          = rlp::encode_u64 (h.gas_limit);
    const auto gas_used_rlp           = rlp::encode_u64 (h.gas_used);
    const auto timestamp_rlp          = rlp::encode_u64 (h.timestamp);

    // extra_data (≤ 32 B) → byte-string RLP over its actual length.
    const auto extra_data_rlp         = rlp::encode(BytesView{h.extra_data.data(),
                                                              h.extra_data.size()});

    const auto prev_randao_rlp        = rlp::encode(BytesView{h.prev_randao.bytes,
                                                              sizeof(h.prev_randao.bytes)});

    // nonce — Ethereum encodes it as an 8-byte FIXED-WIDTH bytestring,
    // not as a trimmed integer. encode() handles the fixed-width path.
    const auto nonce_rlp              = rlp::encode(BytesView{h.nonce.data(),
                                                              h.nonce.size()});

    const auto base_fee_rlp           = rlp::encode_u256(h.base_fee_per_gas);
    const auto withdrawals_root_rlp   = rlp::encode(BytesView{h.withdrawals_root.bytes,
                                                              sizeof(h.withdrawals_root.bytes)});
    const auto blob_gas_used_rlp      = rlp::encode_u64(h.blob_gas_used);
    const auto excess_blob_gas_rlp    = rlp::encode_u64(h.excess_blob_gas);
    const auto parent_beacon_root_rlp = rlp::encode(BytesView{h.parent_beacon_block_root.bytes,
                                                              sizeof(h.parent_beacon_block_root.bytes)});
    const auto requests_hash_rlp      = rlp::encode(BytesView{h.requests_hash.bytes,
                                                              sizeof(h.requests_hash.bytes)});

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

} // namespace

evmc::bytes32 compute_block_header_hash(const BlockHeader& h) {
    const auto rlp_bytes = encode_block_header_rlp(h);
    return keccak256_bytes32(rlp_bytes.data(), rlp_bytes.size());
}

} // namespace zeg

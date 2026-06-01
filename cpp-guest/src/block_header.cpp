#include "zeg/block_header.hpp"

#include "zeg/keccak.hpp"
#include "zeg/rlp.hpp"

namespace zeg {

namespace {

// Build the RLP encoding of an Ethereum block header. Field order
// matches the Yellow Paper (App. L). The header layout grew across
// hardforks — pre-Pectra ancestors omit the trailing post-Cancun /
// post-Pectra fields entirely (not "encoded as zero"). The caller
// passes the fork in `h.fork_id` and the encoder derives the field
// count from it via `fork_field_count` (fork.hpp):
//
//   Prague/Osaka → 21 (adds requests_hash)
//   Cancun       → 20 (adds blob_gas_used, excess_blob_gas,
//                       parent_beacon_block_root)
//   Shanghai     → 17 (adds withdrawals_root)
//   London/Paris → 16 (adds base_fee_per_gas)
//   Berlin       → 15 (pre-London)
//
// Field-value heuristics don't work because a Cancun block with no
// blob transactions and no CL (test-fixture scenario, both
// parent_beacon_block_root and blob counters all zero) is bit-for-bit
// identical to a pre-Cancun block in field values — only the consensus
// fork the block was mined under disambiguates the two. rust-input-gen
// derives the fork from the original Option<> fields on the wire Block
// (plus the node's eth_config for Osaka) and threads it through.
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

    // Build the payload by appending fields up to the fork's field
    // count (derived from h.fork_id via the shared table in fork.hpp).
    const uint32_t field_count = fork_field_count(h.fork_id);
    rlp::Bytes payload;
    auto append = [&](const rlp::Bytes& enc) {
        payload.insert(payload.end(), enc.begin(), enc.end());
    };
    append(parent_hash_rlp);     //  1
    append(ommers_hash_rlp);     //  2
    append(coinbase_rlp);        //  3
    append(state_root_rlp);      //  4
    append(txs_root_rlp);        //  5
    append(receipts_root_rlp);   //  6
    append(logs_bloom_rlp);      //  7
    append(difficulty_rlp);      //  8
    append(number_rlp);          //  9
    append(gas_limit_rlp);       // 10
    append(gas_used_rlp);        // 11
    append(timestamp_rlp);       // 12
    append(extra_data_rlp);      // 13
    append(prev_randao_rlp);     // 14
    append(nonce_rlp);           // 15
    if (field_count >= 16) {
        append(rlp::encode_u256(h.base_fee_per_gas));
    }
    if (field_count >= 17) {
        append(rlp::encode(BytesView{h.withdrawals_root.bytes,
                                     sizeof(h.withdrawals_root.bytes)}));
    }
    if (field_count >= 20) {
        append(rlp::encode_u64(h.blob_gas_used));
        append(rlp::encode_u64(h.excess_blob_gas));
        append(rlp::encode(BytesView{h.parent_beacon_block_root.bytes,
                                     sizeof(h.parent_beacon_block_root.bytes)}));
    }
    if (field_count >= 21) {
        append(rlp::encode(BytesView{h.requests_hash.bytes,
                                     sizeof(h.requests_hash.bytes)}));
    }

    return rlp::encode_list_payload(
        rlp::BytesView{payload.data(), payload.size()}
    );
}

} // namespace

evmc::bytes32 compute_block_header_hash(const BlockHeader& h) {
    const auto rlp_bytes = encode_block_header_rlp(h);
    return keccak256_bytes32(rlp_bytes.data(), rlp_bytes.size());
}

} // namespace zeg

#include "zeg/new_payload_request.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "zeg/block_header.hpp"
#include "zeg/consensus_info.hpp"
#include "zeg/fatal.hpp"
#include "zeg/rlp.hpp"
#include "zeg/ssz.hpp"
#include "zeg/transactions.hpp"
#include "zeg/zisk_state_db.hpp"

namespace zeg {

namespace {

using ssz::Chunk;

constexpr uint64_t kMaxExtraDataBytes = 32;

// VersionedHashes is List[VersionedHash, MAX_BLOB_COMMITMENTS_PER_BLOCK].
constexpr uint64_t kMaxBlobCommitmentsPerBlock = 4096;

// Number of active fields of the two progressive containers.
constexpr unsigned kExecutionPayloadFields  = 19;
constexpr unsigned kExecutionRequestsFields = 5;

Chunk bytes32_root(const evmc::bytes32& v) noexcept { return v; }

Chunk address_root(const evmc::address& a) noexcept {
    Chunk c{};
    std::memcpy(c.bytes, a.bytes, 20);
    return c;
}

Chunk progressive_container_root(std::span<const Chunk> fields) noexcept {
    return ssz::mix_in_active_fields(ssz::merkleize_progressive(fields),
                                     static_cast<unsigned>(fields.size()));
}

Chunk progressive_list_root(std::span<const Chunk> elements) noexcept {
    return ssz::mix_in_length(ssz::merkleize_progressive(elements), elements.size());
}

Chunk container_root(std::span<const Chunk> fields) noexcept {
    return ssz::merkleize(fields, fields.size());
}

Chunk transactions_root(const Transactions& txs) {
    std::vector<Chunk> roots;
    roots.reserve(txs.size());
    for (std::size_t i = 0; i < txs.size(); ++i) {
        roots.push_back(ssz::progressive_byte_list_root(txs.at(i).envelope()));
    }
    return progressive_list_root(roots);
}

Chunk withdrawals_root(const ConsensusInfo& consensus) {
    std::vector<Chunk> roots;
    roots.reserve(consensus.withdrawals_count());
    for (const auto& w : consensus.withdrawals()) {
        const Chunk fields[] = {
            ssz::uint64_root(w.index()),
            ssz::uint64_root(w.validator_index()),
            address_root(w.address()),
            ssz::uint64_root(w.amount_gwei()),
        };
        roots.push_back(container_root(fields));
    }
    return progressive_list_root(roots);
}

// The blob versioned hashes of every type-3 tx, in block order.
Chunk versioned_hashes_root(const Transactions& txs) {
    std::vector<Chunk> hashes;
    for (std::size_t i = 0; i < txs.size(); ++i) {
        const auto& tx = txs.at(i);
        if (tx.type() != Transactions::Type::Blob) continue;
        const auto outer = rlp::decode_item(tx.blob_versioned_hashes_rlp());
        if (outer.kind != rlp::ItemKind::List) {
            fatal("blob_versioned_hashes is not an RLP list");
        }
        rlp::ListIter it{outer.payload};
        while (it.has_next()) {
            const auto item = it.next();
            if (item.kind != rlp::ItemKind::String || item.payload.size() != 32) {
                fatal("blob versioned hash is not 32 bytes");
            }
            Chunk h;
            std::memcpy(h.bytes, item.payload.data(), 32);
            hashes.push_back(h);
        }
    }
    if (hashes.size() > kMaxBlobCommitmentsPerBlock) fatal("too many blob versioned hashes");
    return ssz::mix_in_length(ssz::merkleize(hashes, kMaxBlobCommitmentsPerBlock), hashes.size());
}

// --- execution requests --------------------------------------------------
//
// Each request record is the SSZ serialization of its fixed-size container,
// so its root is the merkleization of its fields sliced from the record.

// Field widths of each request container, in bytes. uint64 fields (8) are
// little-endian in the record, which is already their SSZ chunk packing.
constexpr std::size_t kDepositFields[]        = {48, 32, 8, 96, 8};  // EIP-6110
constexpr std::size_t kWithdrawalFields[]     = {20, 48, 8};         // EIP-7002
constexpr std::size_t kConsolidationFields[]  = {20, 48, 48};        // EIP-7251
constexpr std::size_t kBuilderDepositFields[] = {48, 32, 8, 96};     // EIP-8282
constexpr std::size_t kBuilderExitFields[]    = {20, 48};            // EIP-8282

struct RequestType {
    std::span<const std::size_t> fields;
    std::size_t                  size;
};
constexpr std::size_t sum(std::span<const std::size_t> s) {
    std::size_t n = 0;
    for (auto v : s) n += v;
    return n;
}
constexpr RequestType kRequestTypes[kExecutionRequestsFields] = {
    {kDepositFields,        sum(kDepositFields)},         // 0x00: 192
    {kWithdrawalFields,     sum(kWithdrawalFields)},      // 0x01: 76
    {kConsolidationFields,  sum(kConsolidationFields)},   // 0x02: 116
    {kBuilderDepositFields, sum(kBuilderDepositFields)},  // 0x03: 184
    {kBuilderExitFields,    sum(kBuilderExitFields)},     // 0x04: 68
};

Chunk request_root(const RequestType& t, const uint8_t* record) noexcept {
    Chunk fields[5];
    std::size_t off = 0;
    for (std::size_t i = 0; i < t.fields.size(); ++i) {
        fields[i] = ssz::byte_vector_root({record + off, t.fields[i]});
        off += t.fields[i];
    }
    return container_root({fields, t.fields.size()});
}

// state.requests() holds one `type || records` blob per non-empty type, in
// ascending type order (EIP-7685); absent types are empty lists.
Chunk execution_requests_root(const ZiskStateDB& state) {
    Chunk lists[kExecutionRequestsFields];
    for (auto& l : lists) l = progressive_list_root({});
    int last_type = -1;
    for (const auto& blob : state.requests()) {
        if (blob.empty()) fatal("execution requests: empty request blob");
        const unsigned type = blob[0];
        if (type >= kExecutionRequestsFields || int(type) <= last_type) {
            fatal("execution requests: unknown or out-of-order request type");
        }
        last_type = int(type);
        const RequestType& t = kRequestTypes[type];
        const std::size_t body = blob.size() - 1;
        if (body == 0 || body % t.size != 0) {
            fatal("execution requests: invalid request payload length");
        }
        std::vector<Chunk> roots;
        roots.reserve(body / t.size);
        for (std::size_t off = 1; off < blob.size(); off += t.size) {
            roots.push_back(request_root(t, blob.data() + off));
        }
        lists[type] = progressive_list_root(roots);
    }
    return progressive_container_root(lists);
}

Chunk execution_payload_root(const BlockHeader&   h,
                             const evmc::bytes32& block_hash,
                             const Transactions&  txs,
                             const ConsensusInfo& consensus,
                             const ZiskStateDB&   state) {
    const Chunk fields[kExecutionPayloadFields] = {
        bytes32_root(h.parent_hash),
        address_root(h.coinbase),
        bytes32_root(h.state_root),
        bytes32_root(h.receipts_root),
        ssz::byte_vector_root(h.logs_bloom),
        bytes32_root(h.prev_randao),
        ssz::uint64_root(h.number),
        ssz::uint64_root(h.gas_limit),
        ssz::uint64_root(h.gas_used),
        ssz::uint64_root(h.timestamp),
        ssz::byte_list_root(h.extra_data, kMaxExtraDataBytes),
        ssz::uint256_root(h.base_fee_per_gas),
        bytes32_root(block_hash),
        transactions_root(txs),
        withdrawals_root(consensus),
        ssz::uint64_root(h.blob_gas_used),
        ssz::uint64_root(h.excess_blob_gas),
        ssz::progressive_byte_list_root(state.block_access_list_rlp()),
        ssz::uint64_root(h.slot_number),
    };
    return progressive_container_root(fields);
}

}  // namespace

evmc::bytes32 new_payload_request_root(const BlockHeader&   header,
                                       const evmc::bytes32& block_hash,
                                       const Transactions&  transactions,
                                       const ConsensusInfo& consensus,
                                       const ZiskStateDB&   state) {
    const Chunk fields[] = {
        execution_payload_root(header, block_hash, transactions, consensus, state),
        versioned_hashes_root(transactions),
        bytes32_root(header.parent_beacon_block_root),
        execution_requests_root(state),
    };
    return progressive_container_root(fields);
}

}  // namespace zeg

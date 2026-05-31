// Canonical Pectra-era Ethereum block header — flat carrier of the 21
// fields that go into the header RLP plus a free function that
// computes keccak256(rlp(header)). Used in two places:
//
//   - `PreviousBlocks` builds one of these from each parsed ancestor
//     header (View → BlockHeader) to recompute and chain-verify hashes.
//   - `main()` builds one from the current block's consensus inputs +
//     the post-execution accumulators on `ZiskStateDB` + the freshly
//     computed new state root, to produce the execution-layer block
//     hash for the block under proof.
//
// The struct holds non-owning references for the bytes32 / address /
// uint256be / span fields and plain values for the u64 counters; the
// caller is responsible for keeping the referenced storage alive for
// the duration of the call to `compute_block_header_hash`.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <evmc/evmc.hpp>

namespace zeg {

struct BlockHeader {
    const evmc::bytes32&          parent_hash;
    const evmc::bytes32&          ommers_hash;
    const evmc::address&          coinbase;
    const evmc::bytes32&          state_root;
    const evmc::bytes32&          transactions_root;
    const evmc::bytes32&          receipts_root;
    std::span<const uint8_t, 256> logs_bloom;
    const evmc::uint256be&        difficulty;
    uint64_t                      number;
    uint64_t                      gas_limit;
    uint64_t                      gas_used;
    uint64_t                      timestamp;
    std::span<const uint8_t>      extra_data;
    const evmc::bytes32&          prev_randao;
    std::span<const uint8_t, 8>   nonce;
    const evmc::uint256be&        base_fee_per_gas;
    const evmc::bytes32&          withdrawals_root;
    uint64_t                      blob_gas_used;
    uint64_t                      excess_blob_gas;
    const evmc::bytes32&          parent_beacon_block_root;
    const evmc::bytes32&          requests_hash;
    // How many header fields to RLP-encode. Default is 21 (full Pectra
    // layout). Mixed-fork ancestor chains (e.g. Cancun → Prague EEST
    // transition fixtures) need lower counts for pre-Pectra ancestors:
    //   21 = Pectra (adds requests_hash)
    //   20 = Cancun (adds blob_gas_used, excess_blob_gas, parent_beacon_block_root)
    //   17 = Shanghai (adds withdrawals_root)
    //   16 = London (adds base_fee_per_gas)
    //   15 = pre-London
    // The trailing slots in the struct can be left referencing dummy /
    // zero data when field_count truncates them away; the encoder will
    // ignore them.
    uint32_t                      field_count = 21;
};

// keccak256 of the canonical RLP encoding of `h`. Field order matches
// the Yellow Paper (App. L) — any reorder produces a wrong hash.
evmc::bytes32 compute_block_header_hash(const BlockHeader& h);

} // namespace zeg

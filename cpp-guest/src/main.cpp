// ZisK guest entry point: stateless re-execution of an Ethereum block.
//
// Reads a single private-input stream produced by `rust-input-gen`, replays
// the block against a ZiskStateDB, verifies the pre-execution state root
// against `consensus.parent_hash()`, recomputes the post-execution state
// root and the execution-layer block hash of the block under proof, and
// emits that block hash as the sole public output.
//
// The stream is consumed linearly. Every advance is 8-byte aligned so typed
// pointer casts on the input buffer stay valid.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

#include <evmc/evmc.hpp>

#include "zeg/accounts.hpp"
#include "zeg/binary_format.hpp"     // kMagic
#include "zeg/block_header.hpp"
#include "zeg/consensus_info.hpp"
#include "zeg/contracts.hpp"
#include "zeg/fatal.hpp"
#include "zeg/previous_blocks.hpp"
#include "zeg/state_root.hpp"
#include "zeg/storages.hpp"
#include "zeg/transactions.hpp"
#include "zeg/zisk_state_db.hpp"

namespace {

// ===== I/O =====

// Slurp `path` into an 8-byte-aligned static buffer, verify the leading
// magic, and return a cursor positioned right after the magic prefix.
// The first 8 bytes of the file are `kMagic` (4 B, little-endian) +
// 4 B zero padding so the returned cursor stays 8-byte aligned for the
// typed reads downstream constructors perform via std::assume_aligned<8>.
const uint8_t* read_input_stream(const char* path);

// Emit a 32-byte value to ZisK as a public output.
void emit_public_output(const evmc::bytes32& value);

// ===== Post-merge header constants =====
//
// `ommers_hash` is fixed at keccak256(rlp([])) since The Merge — no
// uncles can ever be included. `difficulty` is zero from The Merge
// onward, and `nonce` is the 8-byte zero string (Pectra inherits both
// from The Merge / Shanghai conventions).
constexpr evmc::bytes32 kEmptyOmmersHash{{
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a,
    0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13,
    0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
}};
constexpr evmc::uint256be       kPostMergeDifficulty{};
constexpr std::array<uint8_t, 8> kPostMergeNonce{};

} // namespace

int main(int argc, char** argv) {
    // 1. Read the entire input stream from the file path passed on
    //    the command line. `read_input_stream` checks the magic and
    //    returns a cursor positioned past the 8-byte magic prefix.
    if (argc < 2) {
        zeg::fatal("usage: zisk_eth_guest <input-file>");
    }
    const uint8_t* cursor = read_input_stream(argv[1]);

    // 2. Parse the six input-stream collections at main level. Stream-
    //    order matters and must match the prover's write order:
    //    contracts → accounts → storages → previous_blocks →
    //    consensus_info → transactions. Each constructor consumes its
    //    section and advances `cursor`.
    zeg::ConsensusInfo  consensus       (cursor);
    zeg::Transactions   transactions    (cursor);
    zeg::Accounts       accounts        (cursor);
    zeg::Contracts      contracts       (cursor);
    zeg::Storages       storages        (cursor);
    zeg::PreviousBlocks previous_blocks (cursor);

    // 3. Anchor the ancestor chain to the block being computed.
    //    PreviousBlocks already verifies block[i].parent_hash ==
    //    hash(block[i+1]) internally; we still need the chain's tip
    //    (block[0]) to match the current block's parent_hash. Skipped
    //    when the prover supplied no ancestors.
    if (!previous_blocks.empty() &&
        consensus.parent_hash() != previous_blocks.hash(0)) {
        zeg::fatal("PreviousBlocks: hash(block[0]) != consensus.parent_hash()");
    }

    // 4. Construct the state DB. ZiskStateDB borrows the five
    //    collections by reference for the rest of the run; Host
    //    callbacks pass data through them (or fatal-stub for overrides
    //    that need infrastructure not yet built).
    zeg::ZiskStateDB state(accounts, consensus, contracts, previous_blocks, storages);

    // 5. Run the whole block: pre-block system calls, every tx, then
    //    post-block side-effects. `state` owns the evmone VM and
    //    journals every state write so a revert at any depth rolls
    //    back cleanly.
    state.execute_block(transactions);

    // 6. Verify the pre-execution state root against the parent
    //    anchor. In this guest's convention `consensus.parent_hash()`
    //    carries the parent state root directly, so it is the expected
    //    value for the old root. Constructing the StateRoot walks the
    //    trie once with the original values, caches the result, and
    //    records the per-NodeR cache entries the new-root pass will
    //    reuse. `cursor` is advanced past every byte consumed.
    zeg::StateRoot state_root(cursor, accounts, storages);
    if (state_root.old_state_root() != consensus.parent_hash()) {
        zeg::fatal("pre-execution state root mismatch");
    }

    // 7. Compute the post-execution state root. calculate_new_state_root
    //    reuses the cache populated above — it does not consume from
    //    `cursor`. The value is no longer verified here against a
    //    prover-supplied root; instead it feeds step 7' as the
    //    `state_root` field of the reconstructed header.
    const evmc::bytes32 new_state_root = state_root.calculate_new_state_root();

    // 7'. Compute the execution-layer block hash of the block under
    //     proof: keccak256(RLP(header)) over the 21 Pectra header
    //     fields. Field sources:
    //       - consensus inputs        ← `consensus`
    //       - post-execution roots    ← `new_state_root`,
    //                                   `transactions.transactions_root()`,
    //                                   `state.{receipts,withdrawals}_root()`
    //       - post-execution counters ← `state.{gas_used, blob_gas_used,
    //                                            block_bloom_filter,
    //                                            requests_hash}()`
    //       - post-merge constants    ← `kEmptyOmmersHash`,
    //                                   `kPostMergeDifficulty`,
    //                                   `kPostMergeNonce`
    //     The result is held locally — step 8 still emits the
    //     prover-supplied consensus block hash, and downstream code
    //     will eventually wire `execution_block_hash` into the
    //     guest's public output.
    const zeg::BlockHeader header{
        .parent_hash              = consensus.parent_hash(),
        .ommers_hash              = kEmptyOmmersHash,
        .coinbase                 = consensus.beneficiary(),
        .state_root               = new_state_root,
        .transactions_root        = transactions.transactions_root(),
        .receipts_root            = state.receipts_root(),
        .logs_bloom               = std::span<const uint8_t, 256>{state.block_bloom_filter()},
        .difficulty               = kPostMergeDifficulty,
        .number                   = consensus.number(),
        .gas_limit                = consensus.gas_limit(),
        .gas_used                 = state.gas_used(),
        .timestamp                = consensus.timestamp(),
        .extra_data               = consensus.extra_data(),
        .prev_randao              = consensus.prev_randao(),
        .nonce                    = std::span<const uint8_t, 8>{kPostMergeNonce},
        .base_fee_per_gas         = consensus.base_fee_per_gas(),
        .withdrawals_root         = state.withdrawals_root(),
        .blob_gas_used            = state.blob_gas_used(),
        .excess_blob_gas          = consensus.excess_blob_gas(),
        .parent_beacon_block_root = consensus.parent_beacon_block_root(),
        .requests_hash            = state.requests_hash(),
    };
    const evmc::bytes32 execution_block_hash =
        zeg::compute_block_header_hash(header);

    // 8. Emit the execution-layer block hash as the sole public output
    //    of this guest run.
    emit_public_output(execution_block_hash);

    return 0;
}

namespace {

// ----- Stubs (to be implemented as the guest is fleshed out) -----

const uint8_t* read_input_stream(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        zeg::fatal("read_input_stream: failed to open input file");
    }
    const std::streamsize size = f.tellg();
    if (size < 8) {
        zeg::fatal("read_input_stream: input file too small for magic");
    }
    f.seekg(0);

    // Back the buffer with std::vector<uint64_t> so its data() is
    // 8-byte aligned — downstream constructors do
    // std::assume_aligned<8> on cursor reads. The static keeps the
    // bytes alive for the rest of main().
    static std::vector<uint64_t> raw;
    raw.resize((static_cast<size_t>(size) + 7) / 8);
    if (!f.read(reinterpret_cast<char*>(raw.data()), size)) {
        zeg::fatal("read_input_stream: short read");
    }
    const auto* base = reinterpret_cast<const uint8_t*>(raw.data());

    uint32_t magic;
    std::memcpy(&magic, base, sizeof(magic));
    if (magic != zeg::kMagic) {
        zeg::fatal("read_input_stream: bad magic (expected ZEG0)");
    }

    // Skip the magic + its 4 B zero padding so the returned cursor
    // is 8-byte aligned.
    return base + 8;
}

void emit_public_output(const evmc::bytes32& value) {
    // Host-build placeholder for the ZisK public-output API: print
    // the 32-byte value as lowercase hex with a 0x prefix, one line.
    std::printf("0x");
    for (uint8_t b : value.bytes) {
        std::printf("%02x", b);
    }
    std::printf("\n");
}

} // namespace

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
#include "zeg/keccak.hpp"
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
    const uint8_t* file_base = cursor - 8;  // back up past the magic+pad

    // 2. Parse the input-stream collections at main level. Stream order
    //    must match the prover's write order: consensus_info →
    //    transactions → contracts → previous_blocks → StateRoot. The
    //    Accounts and Storages tables are no longer separate sections —
    //    they are built dynamically by the StateRoot old-root walk (step 4)
    //    from the leaf payloads, so they're created empty here.
    zeg::ConsensusInfo  consensus       (cursor);
    zeg::Transactions   transactions    (cursor);
    zeg::Contracts      contracts       (cursor);
    zeg::PreviousBlocks previous_blocks (cursor);
    zeg::Accounts       accounts;
    zeg::Storages       storages;

    // 3. Anchor the ancestor chain to the block being computed.
    //    PreviousBlocks[0] must be the parent — every BLOCKHASH
    //    invocation that walks depth d reads index d-1, and the
    //    reconstructed header below uses previous_blocks.hash(0) as
    //    parent_hash. Tie it to our parent notion via state_root:
    //    consensus.parent_hash() carries the parent's state root in
    //    this guest's convention, so it must equal block[0]'s
    //    state_root.
    if (previous_blocks.empty()) {
        zeg::fatal("PreviousBlocks: must include at least the parent block");
    }
    if (previous_blocks.at(0).state_root() != consensus.parent_hash()) {
        zeg::fatal("PreviousBlocks: block[0].state_root != consensus.parent_state_root");
    }

    // 4. Build the Accounts/Storages tables and verify the pre-execution
    //    state root, BEFORE executing. Constructing the StateRoot reads the
    //    section's header counts, appends one table row per keyed leaf
    //    (block-start values), computes the old root, and caches every
    //    node's result for the new-root pass. In this guest's convention
    //    `consensus.parent_hash()` carries the parent state root, so it is
    //    the expected old root — checked here so a bad witness is rejected
    //    before any execution happens. `cursor` is advanced past the section.
    if (std::getenv("ZEG_DUMP_SROOT_OFFSET") != nullptr) {
        std::fprintf(stderr, "SROOT_OFFSET=%zu\n", (size_t)(cursor - file_base));
    }
    zeg::StateRoot state_root(cursor, accounts, storages, consensus.gas_limit());
    if (state_root.old_state_root() != consensus.parent_hash()) {
        zeg::fatal("pre-execution state root mismatch");
    }

    // 5. Construct the state DB. ZiskStateDB borrows the five
    //    collections by reference for the rest of the run; Host
    //    callbacks pass data through them (or fatal-stub for overrides
    //    that need infrastructure not yet built).
    zeg::ZiskStateDB state(accounts, consensus, contracts, previous_blocks, storages);

    // 6. Run the whole block: pre-block system calls, every tx, then
    //    post-block side-effects. `state` owns the evmone VM and
    //    journals every state write so a revert at any depth rolls
    //    back cleanly.
    //
    // DEBUG stage selector via `ZEG_STAGE`. Allows running a subset of
    // the pipeline to isolate which stage produces the divergence:
    //   none  → skip everything (walker/cache sanity test).
    //   pre   → just pre_execute_block (EIP-4788/2935 system calls).
    //   txs   → pre + process_transactions (no withdrawals / requests).
    //   post  → pre + post  (no txs).
    //   full  → everything (default; same as unset).
    const char* stage = std::getenv("ZEG_STAGE");
    const bool stage_set = stage != nullptr;
    const bool skip_exec = stage_set && std::strcmp(stage, "none") == 0;
    if (!stage_set || std::strcmp(stage, "full") == 0) {
        state.execute_block(transactions);
    } else if (std::strcmp(stage, "pre") == 0) {
        state.pre_execute_block_pub();
    } else if (std::strcmp(stage, "txs") == 0) {
        state.pre_execute_block_pub();
        state.process_transactions_pub(transactions);
    } else if (std::strcmp(stage, "post") == 0) {
        state.pre_execute_block_pub();
        state.post_execute_block_pub();
    } else if (std::strcmp(stage, "none") != 0) {
        zeg::fatal("ZEG_STAGE: unknown value");
    }

    // DEBUG: full dump of post-execution state for Python MPT reference.
    if (std::getenv("ZEG_DUMP_ALL") != nullptr) {
        for (uint64_t i = 0; i < accounts.size(); ++i) {
            const auto& a = accounts.address_at(i);
            std::fprintf(stderr, "ACCT %llu addr=", (unsigned long long)i);
            for (uint8_t b : a.bytes) std::fprintf(stderr, "%02x", b);
            std::fprintf(stderr, " nonce=%llu balance=", (unsigned long long)accounts.nonce_at(i));
            const auto bal = accounts.balance_at(i);
            for (uint8_t b : bal.bytes) std::fprintf(stderr, "%02x", b);
            std::fprintf(stderr, " ch=");
            const auto ch = accounts.code_hash_at(i);
            for (uint8_t b : ch.bytes) std::fprintf(stderr, "%02x", b);
            std::fprintf(stderr, "\n");
        }
        for (uint64_t i = 0; i < storages.size(); ++i) {
            const auto& a = storages.address_at(i);
            const auto& p = storages.position_at(i);
            const auto  v = storages.value_at(i);
            std::fprintf(stderr, "SLOT %llu addr=", (unsigned long long)i);
            for (uint8_t b : a.bytes) std::fprintf(stderr, "%02x", b);
            std::fprintf(stderr, " pos=");
            for (uint8_t b : p.bytes) std::fprintf(stderr, "%02x", b);
            std::fprintf(stderr, " val=");
            for (uint8_t b : v.bytes) std::fprintf(stderr, "%02x", b);
            std::fprintf(stderr, "\n");
        }
    }

    // 7. Compute the post-execution state root. calculate_new_state_root
    //    reuses the cache populated above — it does not consume from
    //    `cursor`. The value is no longer verified here against a
    //    prover-supplied root; instead it feeds step 7' as the
    //    `state_root` field of the reconstructed header.
    const evmc::bytes32 new_state_root = state_root.calculate_new_state_root();

    // DEBUG: in `none` mode no mutations were applied — the new walk
    // must reproduce the pre-execution root byte-for-byte.
    if (skip_exec) {
        if (new_state_root != state_root.old_state_root()) {
            zeg::fatal("ZEG_STAGE=none: new_state_root != old_state_root");
        }
        std::fprintf(stderr, "ZEG_STAGE=none OK — new == old\n");
    }
    if (stage_set) {
        std::fprintf(stderr, "ZEG_STAGE=%s new_state_root=0x", stage);
        for (uint8_t b : new_state_root.bytes) std::fprintf(stderr, "%02x", b);
        std::fprintf(stderr, "\n");
        return 0;
    }

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
    // Pre-Paris EEST fixtures pin difficulty / nonce / ommers_hash to
    // arbitrary PoW-era values; post-Merge they're constants. Both
    // come from the manifest's consensus_info section — for mainnet
    // replays the values happen to equal the post-Merge constants
    // (kPostMergeDifficulty=0, kPostMergeNonce=0..0, kEmptyOmmersHash),
    // so behavior is preserved for the RPC-driven path.
    const zeg::BlockHeader header{
        .parent_hash              = previous_blocks.hash(0),
        .ommers_hash              = consensus.ommers_hash(),
        .coinbase                 = consensus.beneficiary(),
        .state_root               = new_state_root,
        .transactions_root        = transactions.transactions_root(),
        .receipts_root            = state.receipts_root(),
        .logs_bloom               = std::span<const uint8_t, 256>{state.block_bloom_filter()},
        .difficulty               = consensus.difficulty(),
        .number                   = consensus.number(),
        .gas_limit                = consensus.gas_limit(),
        .gas_used                 = state.gas_used(),
        .timestamp                = consensus.timestamp(),
        .extra_data               = consensus.extra_data(),
        .prev_randao              = consensus.prev_randao(),
        .nonce                    = consensus.nonce(),
        .base_fee_per_gas         = consensus.base_fee_per_gas(),
        .withdrawals_root         = state.withdrawals_root(),
        .blob_gas_used            = state.blob_gas_used(),
        .excess_blob_gas          = consensus.excess_blob_gas(),
        .parent_beacon_block_root = consensus.parent_beacon_block_root(),
        .requests_hash            = state.requests_hash(),
        // Fork the block runs under. ForkId::Unknown (0 = inputs that
        // pre-date the field) resolves to Prague, the mainnet default.
        // The encoder derives the header field count from this.
        .fork_id                  = consensus.fork_id(),
    };
    // DEBUG: dump every header field so we can compare against chain.
    {
        auto dump32 = [](const char* name, const evmc::bytes32& v) {
            std::fprintf(stderr, "HDR %-25s 0x", name);
            for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", v.bytes[i]);
            std::fprintf(stderr, "\n");
        };
        auto dump_u256 = [](const char* name, const evmc::uint256be& v) {
            std::fprintf(stderr, "HDR %-25s 0x", name);
            for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", v.bytes[i]);
            std::fprintf(stderr, "\n");
        };
        dump32("parent_hash", header.parent_hash);
        dump32("ommers_hash", header.ommers_hash);
        std::fprintf(stderr, "HDR %-25s 0x", "coinbase");
        for (int i = 0; i < 20; ++i) std::fprintf(stderr, "%02x", header.coinbase.bytes[i]);
        std::fprintf(stderr, "\n");
        dump32("state_root", header.state_root);
        dump32("transactions_root", header.transactions_root);
        dump32("receipts_root", header.receipts_root);
        std::fprintf(stderr, "HDR logs_bloom_keccak       0x");
        const auto bh = zeg::keccak256_bytes32(header.logs_bloom.data(), 256);
        for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", bh.bytes[i]);
        std::fprintf(stderr, "\n");
        dump_u256("difficulty", header.difficulty);
        std::fprintf(stderr, "HDR %-25s %llu\n", "number", (unsigned long long)header.number);
        std::fprintf(stderr, "HDR %-25s %llu\n", "gas_limit", (unsigned long long)header.gas_limit);
        std::fprintf(stderr, "HDR %-25s %llu\n", "gas_used", (unsigned long long)header.gas_used);
        std::fprintf(stderr, "HDR %-25s %llu\n", "timestamp", (unsigned long long)header.timestamp);
        std::fprintf(stderr, "HDR %-25s len=%zu data=0x", "extra_data", header.extra_data.size());
        for (auto b : header.extra_data) std::fprintf(stderr, "%02x", b);
        std::fprintf(stderr, "\n");
        dump32("prev_randao", header.prev_randao);
        std::fprintf(stderr, "HDR %-25s 0x", "nonce");
        for (int i = 0; i < 8; ++i) std::fprintf(stderr, "%02x", header.nonce[i]);
        std::fprintf(stderr, "\n");
        dump_u256("base_fee_per_gas", header.base_fee_per_gas);
        dump32("withdrawals_root", header.withdrawals_root);
        std::fprintf(stderr, "HDR %-25s %llu\n", "blob_gas_used", (unsigned long long)header.blob_gas_used);
        std::fprintf(stderr, "HDR %-25s %llu\n", "excess_blob_gas", (unsigned long long)header.excess_blob_gas);
        dump32("parent_beacon_block_root", header.parent_beacon_block_root);
        dump32("requests_hash", header.requests_hash);
    }
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

    // The 4 bytes after the magic are the format version. Reject any
    // mismatch — a v0 input (StateRoot Op::Leaf carried an index) would
    // misparse the trie stream under the v1 counter-derived-index walk.
    uint32_t version;
    std::memcpy(&version, base + 4, sizeof(version));
    if (version != zeg::kVersion) {
        zeg::fatal("read_input_stream: unsupported format version");
    }

    // Skip the magic + version word so the returned cursor is 8-byte
    // aligned.
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

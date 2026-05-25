// ZisK guest entry point: stateless re-execution of an Ethereum block.
//
// Reads a single private-input stream produced by `rust-input-gen`, replays
// the block against a ZiskStateDB, verifies the pre- and post-state roots,
// and emits the consensus block hash as a public output.
//
// The stream is consumed linearly. Every advance is 8-byte aligned so typed
// pointer casts on the input buffer stay valid.

#include <cstdint>

#include <evmc/evmc.hpp>

#include "zeg/accounts.hpp"
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

// Returns the start of the ZisK private-input region. The real ZisK runtime
// will provide this via its zkVM API; for now this is a stub.
const uint8_t* read_input_stream();

// Emit a 32-byte value to ZisK as a public output.
void emit_public_output(const evmc::bytes32& value);

// ===== Header / consensus hash handling =====

// Read the parent block's expected stateRoot from the stream.
evmc::bytes32 parse_expected_old_state_root(const uint8_t*& cursor);

// Read the current block's expected stateRoot from the stream.
evmc::bytes32 parse_expected_new_state_root(const uint8_t*& cursor);

// Read the precomputed consensus block hash, validate it against the
// reconstructed header, and return the canonical 32-byte value.
evmc::bytes32 parse_and_check_consensus_block_hash(const uint8_t*& cursor);

} // namespace

int main() {
    // 1. Read the entire input stream.
    const uint8_t* cursor = read_input_stream();

    // 2. Parse the six input-stream collections at main level. Stream-
    //    order matters and must match the prover's write order:
    //    contracts → accounts → storages → previous_blocks →
    //    consensus_info → transactions. Each constructor consumes its
    //    section and advances `cursor`.
    zeg::Contracts      contracts       (cursor);
    zeg::Accounts       accounts        (cursor);
    zeg::Storages       storages        (cursor);
    zeg::PreviousBlocks previous_blocks (cursor);
    zeg::ConsensusInfo  consensus       (cursor);
    zeg::Transactions   transactions    (cursor);

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

    // 6. Verify the pre-execution state root against the parent header.
    //    Constructing the StateRoot walks the trie once with the
    //    original values, caches the result, and records the per-NodeR
    //    cache entries the new-root pass will reuse. `cursor` is
    //    advanced past every byte consumed.
    const evmc::bytes32 expected_old = parse_expected_old_state_root(cursor);
    zeg::StateRoot state_root(cursor, accounts, storages);
    if (state_root.old_state_root() != expected_old) {
        zeg::fatal("pre-execution state root mismatch");
    }

    // 7. Verify the post-execution state root against the current
    //    header. calculate_new_state_root reuses the cache populated
    //    above — it does not consume from `cursor`.
    const evmc::bytes32 expected_new = parse_expected_new_state_root(cursor);
    const evmc::bytes32 computed_new = state_root.calculate_new_state_root();
    if (computed_new != expected_new) {
        zeg::fatal("post-execution state root mismatch");
    }

    // 8. Parse and verify the consensus block hash, then emit it as the
    //    sole public output of this guest run.
    const evmc::bytes32 consensus_hash = parse_and_check_consensus_block_hash(cursor);
    emit_public_output(consensus_hash);

    return 0;
}

namespace {

// ----- Stubs (to be implemented as the guest is fleshed out) -----

const uint8_t* read_input_stream() {
    // TODO: replace with the ZisK private-input pointer.
    return nullptr;
}

void emit_public_output(const evmc::bytes32&) {
    // TODO: replace with the ZisK public-output API.
}

evmc::bytes32 parse_expected_old_state_root(const uint8_t*&) {
    return {};
}

evmc::bytes32 parse_expected_new_state_root(const uint8_t*&) {
    return {};
}

evmc::bytes32 parse_and_check_consensus_block_hash(const uint8_t*&) {
    return {};
}

} // namespace

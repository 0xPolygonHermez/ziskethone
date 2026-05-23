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

#include "zeg/fatal.hpp"
#include "zeg/zisk_state_db.hpp"

namespace {

// ===== I/O =====

// Returns the start of the ZisK private-input region. The real ZisK runtime
// will provide this via its zkVM API; for now this is a stub.
const uint8_t* read_input_stream();

// Emit a 32-byte value to ZisK as a public output.
void emit_public_output(const evmc::bytes32& value);

// ===== Phase handlers =====
//
// Each handler parses a self-delimited chunk from the stream and applies it
// to `state` using evmone. They advance `cursor` past the consumed bytes
// (multiple of 8) so the caller can chain them.

// Pre-block system calls: EIP-4788 (beacon roots), EIP-2935 (block hashes).
void execute_pre_block(const uint8_t*& cursor, zeg::ZiskStateDB& state);

// Re-execute every user transaction in the block.
void execute_transactions(const uint8_t*& cursor, zeg::ZiskStateDB& state);

// Post-block: withdrawal balance credits + EIP-7002 / EIP-7251 system calls.
void execute_post_block(const uint8_t*& cursor, zeg::ZiskStateDB& state);

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

    // 2. Construct the state DB. The constructor parses accounts, storage
    //    values, contracts, and previous-block headers, advancing `cursor`
    //    past every byte consumed.
    zeg::ZiskStateDB state(cursor);

    // 3. Apply each block-execution phase in protocol order.
    execute_pre_block(cursor, state);
    execute_transactions(cursor, state);
    execute_post_block(cursor, state);

    // 4. Verify the pre-execution state root against the parent header.
    const evmc::bytes32 expected_old = parse_expected_old_state_root(cursor);
    const evmc::bytes32 computed_old = state.calculateOldStateRoot(cursor);
    if (computed_old != expected_old) {
        zeg::fatal("pre-execution state root mismatch");
    }

    // 5. Verify the post-execution state root against the current header.
    const evmc::bytes32 expected_new = parse_expected_new_state_root(cursor);
    const evmc::bytes32 computed_new = state.calculateNewStateRoot(cursor);
    if (computed_new != expected_new) {
        zeg::fatal("post-execution state root mismatch");
    }

    // 6. Parse and verify the consensus block hash, then emit it as the
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

void execute_pre_block(const uint8_t*&, zeg::ZiskStateDB&) {
    // TODO: parse the pre-block descriptor from the stream and use evmone
    // (via state as the Host) to run the EIP-4788 and EIP-2935 system calls.
}

void execute_transactions(const uint8_t*&, zeg::ZiskStateDB&) {
    // TODO: for each tx in the stream, decode + execute under evmone.
}

void execute_post_block(const uint8_t*&, zeg::ZiskStateDB&) {
    // TODO: apply withdrawal balance credits, then EIP-7002 / EIP-7251.
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

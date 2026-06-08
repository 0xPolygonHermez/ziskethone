// instructions.cpp — MOCK opcode handlers + the dispatch table.
//
// SCAFFOLDING ONLY. None of these implement real EVM semantics yet; they exist
// so the dispatch table, the execute() loop, and the evmc result plumbing can
// be wired up and compiled end to end. As real opcodes land, replace the mock
// bodies one at a time. Arithmetic / bitwise opcodes (ADD, MUL, AND, ...) are
// the prime candidates for routing through the ZisK-accelerated zeg::bi backend
// (cpp-guest/zisk/bigint/backend.hpp), since the stack words are already in its
// little-endian uint64_t[4] layout.

#include "instructions.hpp"

namespace zevm {

namespace {

// Default for every opcode without a dedicated handler. Halts the frame with a
// failure status so unknown/unimplemented opcodes are observable rather than
// silently skipped.
bool op_unimplemented(EvmState& s) {
    s.status = EVMC_UNDEFINED_INSTRUCTION;
    return false;  // stop
}

// 0x00 STOP — halt successfully.
bool op_stop(EvmState& s) {
    s.status = EVMC_SUCCESS;
    return false;  // stop
}

// 0xfe INVALID — designated invalid opcode; consumes all gas (real semantics
// will zero gas), halts with failure.
bool op_invalid(EvmState& s) {
    s.status = EVMC_INVALID_INSTRUCTION;
    return false;  // stop
}

// ---- representative no-op mocks, to show the handler shape ----
// These advance pc and continue, but do NOT yet implement their semantics.

// 0x01 ADD — TODO: pop a, b; push a + b (route through zeg::bi::add256).
bool op_add(EvmState& s) {
    ++s.pc;
    return true;
}

// 0x5b JUMPDEST — valid jump target marker; a no-op that just advances pc.
bool op_jumpdest(EvmState& s) {
    ++s.pc;
    return true;
}

// 0x60 PUSH1 — TODO: read 1 immediate byte, push it; advance pc past the data.
bool op_push1(EvmState& s) {
    s.pc += 2;  // opcode + 1 immediate byte
    return true;
}

// Build the full 256-entry table: default every slot to op_unimplemented, then
// slot in the handlers we have. Done at static-init time via a constexpr
// builder so the array is genuinely const with no designated-initializer
// extensions.
constexpr InstrTable build_table() {
    InstrTable t{};
    for (auto& fn : t)
        fn = &op_unimplemented;

    t[0x00] = &op_stop;
    t[0x01] = &op_add;
    t[0x5b] = &op_jumpdest;
    t[0x60] = &op_push1;
    t[0xfe] = &op_invalid;

    return t;
}

}  // namespace

const InstrTable instruction_table = build_table();

}  // namespace zevm

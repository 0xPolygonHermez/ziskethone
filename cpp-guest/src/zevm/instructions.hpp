// instructions.hpp — the 256-entry opcode dispatch table.
//
// Each opcode maps to a handler taking the current EvmState by reference and
// returning whether the execute() loop should continue: `true` => keep going,
// `false` => halt this frame. Handlers advance pc, mutate the stack/memory/gas,
// and set EvmState::status on failure.

#pragma once

#include <array>

#include "evm_state.hpp"

namespace zevm {

// Returns true to continue execution, false to stop the frame.
using InstrFn = bool (*)(EvmState&);

using InstrTable = std::array<InstrFn, 256>;

// One entry per possible opcode byte (0x00..0xff). Every slot is non-null;
// opcodes with no dedicated handler point at op_unimplemented.
extern const InstrTable instruction_table;

}  // namespace zevm

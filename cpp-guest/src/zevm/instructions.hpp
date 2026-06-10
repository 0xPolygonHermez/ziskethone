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

// The dispatch table for revision `rev`. Every slot is non-null; opcodes with no
// dedicated handler — and fork-introduced opcodes not yet available at `rev` —
// point at op_unimplemented (EVMC_UNDEFINED_INSTRUCTION). One table is built per
// revision and cached, so callers hold the reference for a whole frame.
const InstrTable& instruction_table_for(evmc_revision rev);

}  // namespace zevm

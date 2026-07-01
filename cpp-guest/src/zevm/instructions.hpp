// instructions.hpp — opcode-handler contract shared by the per-category headers.
//
// Each opcode is an inline handler taking the current EvmState by reference and
// returning whether the execute() loop should continue: `true` => keep going,
// `false` => halt this frame. Handlers advance pc, mutate the stack/memory/gas,
// and set EvmState::status on failure. They live in instructions/<category>.inl.hpp
// (namespace zevm::<category>_ops) and are dispatched by the per-fork switch in
// zevm.cpp — there is no runtime dispatch table.

#pragma once

#include "evm_state.hpp"

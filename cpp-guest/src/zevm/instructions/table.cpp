// table.cpp — assembles the 256-entry opcode dispatch table.
//
// Defaults every slot to op_unimplemented, then lets each opcode category slot
// in its handlers via register_*(). Built once at static-init time (the
// registrars live in other translation units, so this can't be constexpr); the
// result is const for the rest of the run. See instructions.hpp for the type and
// instructions/detail.hpp for the registrar declarations.

#include "detail.hpp"

namespace zevm {

namespace {

// Default for every opcode without a dedicated handler. Halts the frame with a
// failure status so unknown/unimplemented opcodes are observable rather than
// silently skipped.
bool op_unimplemented(EvmState& s) {
    s.status = EVMC_UNDEFINED_INSTRUCTION;
    return false;  // stop
}

InstrTable build_table() {
    InstrTable t{};
    for (auto& fn : t)
        fn = &op_unimplemented;

    register_arith(t);
    register_bitwise(t);
    register_keccak(t);
    register_env(t);
    register_memory(t);
    register_storage(t);
    register_control(t);
    register_stack(t);
    register_push(t);
    register_log(t);
    register_system(t);

    return t;
}

}  // namespace

const InstrTable instruction_table = build_table();

}  // namespace zevm

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

// Build the table for `rev`. Categories that gate opcodes by fork (bitwise,
// storage, system) take `rev` and simply skip registering an opcode introduced
// later — it stays op_unimplemented (undefined, no gas), exactly as evmone
// treats an opcode absent from a revision's table.
InstrTable build_table(evmc_revision rev) {
    InstrTable t{};
    for (auto& fn : t)
        fn = &op_unimplemented;

    register_arith(t);
    register_bitwise(t, rev);
    register_keccak(t);
    register_env(t, rev);
    register_memory(t, rev);
    register_storage(t, rev);
    register_control(t);
    register_stack(t);
    register_push(t, rev);
    register_log(t);
    register_system(t, rev);

    return t;
}

}  // namespace

const InstrTable& instruction_table_for(evmc_revision rev) {
    // One table per revision, built on first use. The active revision is constant
    // for a whole block, so in practice this builds at most once per run.
    static InstrTable cache[EVMC_MAX_REVISION + 1];
    static bool       built[EVMC_MAX_REVISION + 1] = {};
    const int i = static_cast<int>(rev);
    if (!built[i]) {
        cache[i] = build_table(rev);
        built[i] = true;
    }
    return cache[i];
}

}  // namespace zevm

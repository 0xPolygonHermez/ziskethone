// zevm.cpp — evmc_vm glue and the top-level execution loop.
//
// This file implements the evmc C-ABI surface (the same one evmone exposes) and
// the interpreter dispatch loop the user specified: construct an EvmState, then
// repeatedly fetch the opcode at pc and call its handler until one returns
// false. Opcode semantics live in instructions.cpp (currently mocks).

#include "zevm.hpp"

#include "evm_state.hpp"
#include "instructions.hpp"

namespace zevm {

namespace {

// The interpreter loop. Builds an evmc_result from the frame's final state.
evmc_result execute(evmc_vm* /*vm*/,
                    const evmc_host_interface* host,
                    evmc_host_context* context,
                    evmc_revision rev,
                    const evmc_message* msg,
                    const uint8_t* code,
                    size_t code_size) noexcept {
    EvmState state(msg, code, code_size, host, context, rev);

    bool cont = true;
    do {
        // Past the end of code behaves like STOP (opcode 0x00).
        const uint8_t opcode =
            state.pc < state.codeSize ? state.code[state.pc] : 0x00;
        cont = instruction_table[opcode](state);
    } while (cont);

    // Scaffold result: report the frame's status and remaining gas, no output.
    // Real RETURN/REVERT data handling (and a release() for owned output
    // buffers) will be added with the memory/return opcodes.
    evmc_result result{};
    result.status_code = state.status;
    result.gas_left =
        (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT)
            ? state.gas
            : 0;
    result.gas_refund = 0;
    result.output_data = nullptr;
    result.output_size = 0;
    result.release = nullptr;
    return result;
}

void destroy(evmc_vm* /*vm*/) noexcept {
    // The VM instance is a single static object (see evmc_create_zevm); nothing
    // to free.
}

evmc_capabilities_flagset get_capabilities(evmc_vm* /*vm*/) noexcept {
    return EVMC_CAPABILITY_EVM1;
}

}  // namespace

}  // namespace zevm

extern "C" struct evmc_vm* evmc_create_zevm(void) EVMC_NOEXCEPT {
    static struct evmc_vm vm = {
        EVMC_ABI_VERSION,
        "zevm",
        "0.0.1",
        zevm::destroy,
        zevm::execute,
        zevm::get_capabilities,
        nullptr,  // set_option: unsupported
    };
    return &vm;
}

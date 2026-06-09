// zevm.cpp — evmc2 glue and the top-level execution loop.
//
// Implements the evmc2 surface for the hand-written EVM: the base evmc ops
// (execute / destroy / get_capabilities) plus the evmc2 extensions (prepare /
// execute2 / release_pre_execution). The interpreter dispatch loop the user
// specified — construct an EvmState, then repeatedly fetch the opcode at pc and
// call its handler until one returns false — lives in run(), parameterized by an
// optional precomputed JUMPDEST analysis. Opcode semantics live in
// instructions.cpp (currently mostly mocks).

#include "zevm.hpp"

#include <cstdlib>

#include "evm_mem.hpp"     // EVMMem::data — the frame's output window
#include "evm_state.hpp"
#include "instructions.hpp"

namespace zevm {

namespace {

// zevm's evmc2_pre_execution: the first-instruction-per-32-byte-chunk map for
// one bytecode (ceil(code_size/32) bytes; see mark_first_instruction_in_word).
struct Analysis {
    uint8_t* firstInstr = nullptr;
};

// Run one frame to completion and build its evmc_result. `prebuilt` is an
// optional JUMPDEST map borrowed for this frame; when null, EvmState builds its
// own.
evmc_result run(const evmc_host_interface* host, evmc_host_context* context,
                evmc_revision rev, const evmc_message* msg,
                const uint8_t* code, size_t code_size,
                const uint8_t* prebuilt) noexcept {
    EvmState state(msg, code, code_size, host, context, rev, prebuilt);

    bool cont = true;
    do {
        // Past the end of code behaves like STOP (opcode 0x00).
        const uint8_t opcode =
            state.pc < state.codeSize ? state.code[state.pc] : 0x00;
        cont = instruction_table[opcode](state);
    } while (cont);

    // Report status, remaining gas, refund, and the RETURN/REVERT output. The
    // output points straight into this frame's EVMMem zone (set by
    // op_return/op_revert) with no release: the bytes are conserved after the
    // frame is popped because the caller is in the other zone (depth parity) and
    // copies/consumes them before reusing this zone. The pointer is captured here
    // while the frame is still the active EVMMem handle.
    evmc_result result{};
    result.status_code = state.status;
    result.gas_left =
        (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT) ? state.gas : 0;
    result.gas_refund = (state.status == EVMC_SUCCESS) ? state.gas_refund : 0;
    result.output_data = state.output_size != 0 ? EVMMem::data(state.output_offset) : nullptr;
    result.output_size = state.output_size;
    result.release = nullptr;
    return result;
}

// ----- base evmc operations -----

evmc_result w_execute(evmc_vm* /*vm*/, const evmc_host_interface* host,
                      evmc_host_context* context, evmc_revision rev,
                      const evmc_message* msg, const uint8_t* code,
                      size_t code_size) noexcept {
    return run(host, context, rev, msg, code, code_size, /*prebuilt=*/nullptr);
}

void w_destroy(evmc_vm* /*vm*/) noexcept {
    // The VM instance is a single static object (see evmc2_create_zevm); nothing
    // to free.
}

evmc_capabilities_flagset w_get_capabilities(evmc_vm* /*vm*/) noexcept {
    return EVMC_CAPABILITY_EVM1;
}

// ----- evmc2 extensions -----

evmc2_pre_execution* w_prepare(evmc_vm* /*vm*/, const uint8_t* code,
                               size_t code_size) noexcept {
    auto* a = new Analysis{};
    if (code_size != 0) {
        a->firstInstr = static_cast<uint8_t*>(std::calloc((code_size + 31) / 32, 1));
        mark_first_instruction_in_word(code, code_size, a->firstInstr);
    }
    return reinterpret_cast<evmc2_pre_execution*>(a);
}

void w_release(evmc_vm* /*vm*/, evmc2_pre_execution* pre) noexcept {
    auto* a = reinterpret_cast<Analysis*>(pre);
    std::free(a->firstInstr);
    delete a;
}

evmc_result w_execute2(evmc_vm* /*vm*/, const evmc_host_interface* host,
                       evmc_host_context* context, evmc_revision rev,
                       const evmc_message* msg, const uint8_t* code,
                       size_t code_size, evmc2_pre_execution* pre) noexcept {
    const uint8_t* prebuilt =
        pre != nullptr ? reinterpret_cast<Analysis*>(pre)->firstInstr : nullptr;
    return run(host, context, rev, msg, code, code_size, prebuilt);
}

}  // namespace

}  // namespace zevm

extern "C" evmc2_vm* evmc2_create_zevm(void) {
    static evmc2_vm vm = {
        /*base=*/ {
            EVMC_ABI_VERSION,
            "zevm",
            "0.0.1",
            zevm::w_destroy,
            zevm::w_execute,
            zevm::w_get_capabilities,
            nullptr,  // set_option: unsupported
        },
        zevm::w_prepare,
        zevm::w_execute2,
        zevm::w_release,
    };
    return &vm;
}

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

// zevm's evmc2_pre_execution handle IS the first-instruction-per-32-byte-chunk
// map itself: ceil(code_size/32) malloc'd bytes (see
// mark_first_instruction_in_word), cast to/from the opaque handle type — no
// wrapper struct. Null when code_size == 0 (nothing to analyze).

// One preallocated frame per call depth, reused across calls (the call stack has
// exactly one live frame per depth). Static (not heap): the trivial EvmState
// makes this plain zeroed BSS. run() reset()s the slot on entry, teardown()s it
// on return. Indexed by msg->depth — the same index EVMMem uses for its zones,
// so the existing depth-limit light-fail keeps it in range.
EvmState g_frames[kMaxCallDepth];

// Run one frame to completion and build its evmc_result. `prebuilt` is an
// optional JUMPDEST map borrowed for this frame; when null, EvmState builds its
// own.
evmc_result run(const evmc_host_interface* host, evmc_host_context* context,
                evmc_revision rev, const evmc_message* msg,
                const uint8_t* code, size_t code_size,
                const uint8_t* prebuilt) noexcept {
    // Use this depth's preallocated frame and reset it for the call. EvmState is
    // large (~34 KB — it embeds the 1024-entry operand stack); the static array
    // keeps it off both the native C++ stack (a nested CALL re-enters run()
    // recursively, so on-stack frames would overflow the thread stack near max
    // depth) and the heap (no per-frame allocation).
    EvmState& state = g_frames[msg->depth];
    state.reset(msg, code, code_size, host, context, rev, prebuilt);

    // Dispatch table for this revision (fork-gated opcodes resolved at build).
    const InstrTable& itable = instruction_table_for(rev);

    bool cont = true;
    do {
        // Past the end of code behaves like STOP (opcode 0x00).
        const uint8_t opcode =
            state.pc < state.codeSize ? state.code[state.pc] : 0x00;
        cont = itable[opcode](state);
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

    // Release the frame (pop its EVMMem zone, free an owned chunk map, release any
    // held sub-call result). The output pointer above was captured while the frame
    // was active; its bytes stay conserved in the popped zone (depth parity).
    state.teardown();
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
    if (code_size == 0)
        return nullptr;
    // malloc (not calloc): mark_first_instruction_in_word writes every byte.
    auto* map = static_cast<uint8_t*>(std::malloc((code_size + 31) / 32));
    mark_first_instruction_in_word(code, code_size, map);
    return reinterpret_cast<evmc2_pre_execution*>(map);
}

void w_release(evmc_vm* /*vm*/, evmc2_pre_execution* pre) noexcept {
    std::free(pre);
}

evmc_result w_execute2(evmc_vm* /*vm*/, const evmc_host_interface* host,
                       evmc_host_context* context, evmc_revision rev,
                       const evmc_message* msg, const uint8_t* code,
                       size_t code_size, evmc2_pre_execution* pre) noexcept {
    return run(host, context, rev, msg, code, code_size,
               reinterpret_cast<const uint8_t*>(pre));
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

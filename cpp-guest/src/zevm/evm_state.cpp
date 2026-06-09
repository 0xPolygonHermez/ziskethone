// evm_state.cpp — EvmState construction, teardown, and bytecode analysis.

#include "evm_state.hpp"

#include <cstdlib>
#include <cstring>

#include "evm_mem.hpp"

namespace zevm {

void build_jumpdests(const uint8_t* code, size_t codeSize, uint8_t* out) {
    // PUSH1 (0x60) .. PUSH32 (0x7f): the opcode is followed by 1..32 immediate
    // bytes that must not be scanned for opcodes. JUMPDEST is 0x5b.
    constexpr uint8_t PUSH1 = 0x60;
    constexpr uint8_t PUSH32 = 0x7f;
    constexpr uint8_t JUMPDEST = 0x5b;

    for (size_t i = 0; i < codeSize;) {
        const uint8_t op = code[i];
        if (op == JUMPDEST) {
            out[i] = 1;
            ++i;
        } else if (op >= PUSH1 && op <= PUSH32) {
            i += static_cast<size_t>(op - PUSH1) + 2;  // opcode + immediate data
        } else {
            ++i;
        }
    }
}

EvmState::EvmState(const evmc_message* msg,
                   const uint8_t* code_, size_t codeSize_,
                   const evmc_host_interface* host_,
                   evmc_host_context* ctx_,
                   evmc_revision rev_,
                   const uint8_t* prebuilt_analysis)
    : code(code_),
      codeSize(codeSize_),
      gas(msg ? msg->gas : 0),
      evmcMsg(msg),
      host(host_),
      context(ctx_),
      rev(rev_) {
    if (prebuilt_analysis != nullptr) {
        analyzedCode = prebuilt_analysis;  // borrowed (e.g. from evmc2 prepare)
        ownsAnalysis = false;
    } else if (codeSize != 0) {
        // One JUMPDEST-map byte per code byte. Zero-initialized, then filled.
        auto* buf = static_cast<uint8_t*>(std::calloc(codeSize, 1));
        build_jumpdests(code, codeSize, buf);
        analyzedCode = buf;
        ownsAnalysis = true;
    }

    // Push this frame's memory onto the static manager. Nested EvmStates are
    // created/destroyed strictly LIFO, matching EVMMem's stack discipline.
    memHandle = EVMMem::createMemory();
}

EvmState::~EvmState() {
    EVMMem::destroyMemory();
    if (ownsAnalysis)
        std::free(const_cast<uint8_t*>(analyzedCode));
    // Release the last sub-call's result if it owns its output (precompiles);
    // a zevm child's output lives in EVMMem and has no release.
    if (returnDataOwner.release)
        returnDataOwner.release(&returnDataOwner);
}

}  // namespace zevm

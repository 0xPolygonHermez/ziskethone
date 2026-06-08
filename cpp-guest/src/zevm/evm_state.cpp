// evm_state.cpp — EvmState construction, teardown, and bytecode analysis.

#include "evm_state.hpp"

#include <cstdlib>
#include <cstring>

#include "evm_mem.hpp"

namespace zevm {

EvmState::EvmState(const evmc_message* msg,
                   const uint8_t* code_, size_t codeSize_,
                   const evmc_host_interface* host_,
                   evmc_host_context* ctx_,
                   evmc_revision rev_)
    : code(code_),
      codeSize(codeSize_),
      gas(msg ? msg->gas : 0),
      evmcMsg(msg),
      host(host_),
      context(ctx_),
      rev(rev_) {
    // One JUMPDEST-map byte per code byte. Zero-initialized; analyze() fills it.
    analyzedCode = codeSize ? static_cast<uint8_t*>(std::calloc(codeSize, 1))
                            : nullptr;
    analyze();

    // Push this frame's memory onto the static manager. Nested EvmStates are
    // created/destroyed strictly LIFO, matching EVMMem's stack discipline.
    memHandle = EVMMem::createMemory();
}

EvmState::~EvmState() {
    EVMMem::destroyMemory();
    std::free(analyzedCode);
}

void EvmState::analyze() {
    if (!analyzedCode)
        return;

    // PUSH1 (0x60) .. PUSH32 (0x7f): the opcode is followed by 1..32 immediate
    // bytes that must not be scanned for opcodes. JUMPDEST is 0x5b.
    constexpr uint8_t PUSH1 = 0x60;
    constexpr uint8_t PUSH32 = 0x7f;
    constexpr uint8_t JUMPDEST = 0x5b;

    for (size_t i = 0; i < codeSize;) {
        const uint8_t op = code[i];
        if (op == JUMPDEST) {
            analyzedCode[i] = 1;
            ++i;
        } else if (op >= PUSH1 && op <= PUSH32) {
            i += static_cast<size_t>(op - PUSH1) + 2;  // opcode + immediate data
        } else {
            ++i;
        }
    }
}

}  // namespace zevm

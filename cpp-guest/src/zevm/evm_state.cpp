// evm_state.cpp — EvmState construction, teardown, and bytecode analysis.

#include "evm_state.hpp"

#include <cstdlib>
#include <cstring>

#include "evm_mem.hpp"

namespace zevm {

void mark_first_instruction_in_word(const uint8_t* code, size_t codeSize, uint8_t* out) {
    // For each 32-byte chunk, store the offset (0..31) of its first instruction —
    // the first byte that is an opcode, not PUSH immediate data — or 32 if the
    // chunk has none (it's entirely the continuation of a PUSH from an earlier
    // chunk). `out` holds ceil(codeSize/32) bytes. This lets is_jumpdest begin a
    // local parse near any position instead of scanning from the start of code.
    constexpr uint8_t PUSH1 = 0x60;
    const size_t nWords = (codeSize + 31) / 32;
    if (nWords == 0)
        return;  // empty code (callers also guard this)

    const uint8_t* p          = code;  // next instruction boundary
    const uint8_t* chunkStart = code;  // start of the chunk being recorded

    // Full chunks (all but the last): every byte walked is within the code, so
    // the inner walk needs no end check.
    for (size_t i = 0; i + 1 < nWords; ++i) {
        out[i] = static_cast<uint8_t>(p - chunkStart);  // 0..32 (32 == no instruction)
        chunkStart += 32;
        while (p < chunkStart) {  // advance past PUSH data to the next chunk's first opcode
            const uint8_t op = *p;
            p += (static_cast<int8_t>(op) >= static_cast<int8_t>(PUSH1))
                     ? static_cast<size_t>(op - PUSH1) + 2   // opcode + immediate bytes
                     : 1;
        }
    }
    // Last (possibly partial) chunk: its first instruction may be past the code
    // (a PUSH truncated at the end) -> 32. No walk needed; nothing follows it.
    out[nWords - 1] = p < code + codeSize ? static_cast<uint8_t>(p - chunkStart) : 32;
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
        // First-instruction-per-32-byte-chunk map: ceil(codeSize/32) bytes.
        auto* buf = static_cast<uint8_t*>(std::calloc((codeSize + 31) / 32, 1));
        mark_first_instruction_in_word(code, codeSize, buf);
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

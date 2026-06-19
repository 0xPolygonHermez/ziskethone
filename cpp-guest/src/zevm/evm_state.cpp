// evm_state.cpp — EvmState construction, teardown, and bytecode analysis.

#include "evm_state.hpp"

#include <cstdlib>
#include <cstring>

#include "evm_mem.hpp"

namespace zevm {

// Instruction width for the JUMPDEST boundary walk: PUSH1..PUSH32 (0x60..0x7f)
// span 1 opcode byte + (op-0x5f) immediate data bytes; every other opcode is 1
// byte. The PUSH range is exactly the opcodes whose top three bits are 0b011, so
// `(op & 0xe0) == 0x60` detects it — and `op - 0x5e` (= op-0x60+2) is the span.
// Kept in 64-bit ops throughout: the old `int8_t(op) >= int8_t(0x60)` sign-trick
// compiled to a per-byte slliw+sraiw sign-extend, which dominated this guest's
// `signextend_w` cost (~4.3M word-ops); this form emits none.
inline size_t instr_width(uint8_t op) {
    return ((op & 0xe0) == 0x60) ? static_cast<size_t>(op) - 0x5e : size_t{1};
}

void build_jumpdest_bitset(const uint8_t* code, size_t codeSize, uint64_t* out) {
    // One bit per code byte: bit i set iff code[i] is a real JUMPDEST (a 0x5b
    // opcode, not PUSH immediate data). Built 64 bytes at a time — each group
    // fills a whole u64 in a register, written with one aligned store (no
    // read-modify-write per JUMPDEST).
    //
    // The inner loop walks *instruction boundaries*, not every byte: a PUSH
    // advances `b` by 1 + its immediate-byte count in one step (those data bytes
    // stay 0 in the word), so push-heavy code — constants, address literals —
    // isn't scanned byte by byte. A PUSH near a group's end can run past byte 64;
    // `start` carries that overrun (always < 64, since the longest span is
    // PUSH32 = 33 bytes) into the next group's first non-data offset.
    //
    // `out` holds ceil(codeSize/64) words. The first codeSize/64 groups are full
    // 64-byte runs guaranteed inside `code`; a trailing partial group
    // (codeSize % 64 bytes) is handled at the end. PUSH1 (0x60) .. PUSH32 (0x7f)
    // is detected by its top-three-bits signature (see instr_width). The walk
    // uses a running pointer `p` (a monotonic instruction cursor, as cheap as the
    // old chunk analysis); the JUMPDEST bit within the group is `p - gStart`.
    const size_t nFull = codeSize / 64;
    const size_t rem   = codeSize % 64;

    const uint8_t* p = code;  // monotonic instruction cursor (carries PUSH overrun)
    for (size_t g = 0; g < nFull; ++g) {
        const uint8_t* const gStart = code + g * 64;
        const uint8_t* const gEnd   = gStart + 64;
        uint64_t word = 0;
        while (p < gEnd) {
            const uint8_t op = *p;
            if (op == 0x5b)
                word |= uint64_t{1} << static_cast<unsigned>(p - gStart);
            p += instr_width(op);
        }
        out[g] = word;
    }
    if (rem) {
        const uint8_t* const gStart = code + nFull * 64;
        const uint8_t* const gEnd   = code + codeSize;
        uint64_t word = 0;
        while (p < gEnd) {
            const uint8_t op = *p;
            if (op == 0x5b)
                word |= uint64_t{1} << static_cast<unsigned>(p - gStart);
            p += instr_width(op);
        }
        out[nFull] = word;
    }
}

void EvmState::reset(const evmc_message* msg,
                     const uint8_t* code_, size_t codeSize_,
                     const evmc_host_interface* host_,
                     evmc_host_context* ctx_,
                     evmc_revision rev_,
                     const uint64_t* prebuilt_analysis) {
    // Every field is set explicitly: a slot reused from run()'s static frame
    // array carries the previous frame's values, and EvmState has no in-class
    // member initializers. stack[] is intentionally left untouched — only
    // entries below stackPointer are read, and pushes write them first.
    pc            = 0;
    code          = code_;
    codeSize      = codeSize_;
    stackPointer  = kStackLimit;
    gas           = msg ? msg->gas : 0;
    gas_refund    = 0;
    evmcMsg       = msg;
    evmcResult    = nullptr;
    lastResult    = nullptr;
    host          = host_;
    context       = ctx_;
    rev           = rev_;
    output_offset = 0;
    output_size   = 0;
    returnDataOwner = evmc_result{};
    status        = EVMC_SUCCESS;

    if (prebuilt_analysis != nullptr) {
        jumpdestBitset = prebuilt_analysis;  // borrowed (e.g. from evmc2 prepare)
        ownsAnalysis   = false;
    } else if (codeSize != 0) {
        // JUMPDEST bitset: ceil(codeSize/64) u64 words. malloc (not calloc):
        // build_jumpdest_bitset writes every word.
        const size_t nWords = (codeSize + 63) / 64;
        auto* buf = static_cast<uint64_t*>(std::malloc(nWords * sizeof(uint64_t)));
        build_jumpdest_bitset(code, codeSize, buf);
        jumpdestBitset = buf;
        ownsAnalysis   = true;
    } else {
        jumpdestBitset = nullptr;
        ownsAnalysis   = false;
    }

    // Push this frame's memory onto the static manager. Frames are reset/torn
    // down strictly LIFO, matching EVMMem's stack discipline.
    memHandle = EVMMem::createMemory();
}

void EvmState::teardown() {
    if (memHandle != -1) {
        EVMMem::destroyMemory();
        memHandle = -1;
    }
    if (ownsAnalysis) {
        std::free(const_cast<uint64_t*>(jumpdestBitset));
        jumpdestBitset = nullptr;
        ownsAnalysis   = false;
    }
    // Release the last sub-call's result if it owns its output (precompiles);
    // a zevm child's output lives in EVMMem and has no release.
    if (returnDataOwner.release) {
        returnDataOwner.release(&returnDataOwner);
        returnDataOwner = evmc_result{};
    }
}

}  // namespace zevm

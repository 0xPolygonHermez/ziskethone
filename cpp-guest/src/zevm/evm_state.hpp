// evm_state.hpp — core mutable state of one zevm execution frame.
//
// zevm is a hand-written EVM intended as a drop-in replacement for evmone at
// the evmc C-ABI boundary (see zevm.hpp / evmc_create_zevm). This first pass is
// scaffolding: the struct and the execution loop exist, but the opcode handlers
// are mocks (instructions.cpp). The layout is chosen so that, once real opcode
// semantics land, 256-bit arithmetic and bitwise ops can be routed through the
// ZisK-accelerated zeg::bi backend (cpp-guest/zisk/bigint/backend.hpp): stack
// words are little-endian uint64_t[4], exactly the limb layout that backend
// expects.

#pragma once

#include <cstddef>
#include <cstdint>

#include <evmc/evmc.h>

#include "u256.hpp"

namespace zevm {

inline constexpr size_t kStackLimit = 1024;

// Fill `out` (ceil(codeSize/32) bytes) with the per-32-byte-chunk first-
// instruction map: out[w] is the offset (0..31) of the first real opcode in
// chunk w, or 32 if the chunk is entirely PUSH continuation. With `code` this
// decides valid JUMPDESTs by a short local parse (see EvmState::is_jumpdest).
// Shared by EvmState's own analysis and by the evmc2 `prepare` path, which
// precomputes it once per distinct bytecode.
void mark_first_instruction_in_word(const uint8_t* code, size_t codeSize, uint8_t* out);

// All the mutable state of a single call frame. One EvmState is created per
// execute() invocation (top-level call or nested CALL/CREATE) and destroyed
// when the frame returns.
struct EvmState {
    // ----- program counter & code -----
    size_t         pc = 0;
    const uint8_t* code = nullptr;     // borrowed; owned by the caller
    size_t         codeSize = 0;

    // First-instruction-per-chunk map (ceil(codeSize/32) bytes): analyzedCode[w]
    // is the offset of chunk w's first opcode, or 32 if none (see
    // mark_first_instruction_in_word). With `code` it decides valid JUMPDESTs
    // (see is_jumpdest). Either borrowed from a precomputed evmc2 analysis (when
    // one is passed to the ctor) or owned (allocated + filled by the ctor, freed
    // by the dtor).
    const uint8_t* analyzedCode = nullptr;
    bool           ownsAnalysis = false;

    // ----- operand stack -----
    // 256-bit words. stackPointer follows the spec's convention: it counts
    // DOWN from kStackLimit (empty) toward 0 (full). A push pre-decrements,
    // a pop post-increments. Number of live items == kStackLimit - stackPointer.
    U256           stack[kStackLimit];
    uint32_t       stackPointer = kStackLimit;   // kStackLimit == empty

    // Per-entry endianness of stack[i] (lazy-endianness optimization): 0 == LE
    // (standard limbs, what zeg::bi consumes), 1 == BE (byteswap256 of the value
    // — the 32 big-endian wire bytes loaded directly, what MLOAD/PUSH produce and
    // MSTORE writes). Conversions are deferred until an op needs a given form.
    // Only entries below stackPointer are live; the rest are stale.
    uint8_t        stackBE[kStackLimit];

    // ----- memory -----
    // Handle into the static EVMMem manager (== this frame's call depth). The
    // frame's bytes live in one of EVMMem's two zones; access goes through
    // EVMMem::readBytes/writeBytes, which use the current top handle. Set by the ctor
    // (createMemory), released by the dtor (destroyMemory).
    int            memHandle = -1;

    // ----- gas -----
    int64_t        gas = 0;
    // Accumulated gas refund (SSTORE clears, etc.; may go negative). Reported in
    // the frame's evmc_result on success; the host applies the EIP-3529 cap.
    int64_t        gas_refund = 0;

    // ----- evmc plumbing -----
    const evmc_message*           evmcMsg = nullptr;   // borrowed (this frame's message)
    evmc_result*                  evmcResult = nullptr; // result being built for this frame
    evmc_result*                  lastResult = nullptr; // result of the most recent sub-call
    const evmc_host_interface*    host = nullptr;       // borrowed
    evmc_host_context*            context = nullptr;    // borrowed
    evmc_revision                 rev = EVMC_FRONTIER;

    // ----- output & return data -----
    // RETURN/REVERT set the frame's output region (a window into memory); run()
    // copies it into the evmc_result. output_size == 0 means no output.
    size_t         output_offset = 0;
    size_t         output_size   = 0;
    // The most recent sub-call's result (CALL family), whose output_data/
    // output_size back RETURNDATASIZE / RETURNDATACOPY — no copy. A zevm child
    // runs at depth+1, i.e. the *other* EVMMem zone (depth parity), which the
    // parent never writes, so its output is conserved until the parent's next
    // call. Released when superseded or at teardown — which only does work for a
    // precompile's output (heap-owned: malloc'd, release set); a zevm child's
    // output lives in EVMMem and has no release.
    evmc_result    returnDataOwner{};

    // ----- execution control -----
    // The status the frame will report back to evmc. Handlers set this before
    // halting; the execute() loop turns it into the returned evmc_result.
    evmc_status_code status = EVMC_SUCCESS;

    // Is `pos` a valid jump target — in code, a JUMPDEST (0x5b) opcode, and not
    // inside PUSH data? Quick-rejects non-0x5b, then parses forward from the
    // first instruction of pos's chunk; if that instruction is past pos (pos is
    // PUSH continuation), the covering PUSH started in the previous chunk, so one
    // step back always lands on a real instruction <= pos. pos is a real opcode
    // iff the parse lands exactly on it. Used by JUMP / JUMPI.
    bool is_jumpdest(size_t pos) const {
        if (pos >= codeSize || code[pos] != 0x5b)
            return false;
        size_t chunk = pos >> 5;       // pos / 32
        size_t base  = chunk << 5;     // chunk * 32
        if (base + analyzedCode[chunk] > pos) {  // first instruction past pos -> back up one chunk
            --chunk;
            base -= 32;
        }
        size_t p = base + analyzedCode[chunk];
        while (p < pos) {
            const uint8_t op = code[p];
            p += (static_cast<int8_t>(op) >= static_cast<int8_t>(0x60))
                     ? static_cast<size_t>(op - 0x60) + 2
                     : 1;
        }
        return p == pos;
    }

    // Creates and initializes the frame. If `prebuilt_analysis` is non-null it is
    // borrowed as the JUMPDEST bitmap (ceil(codeSize/8) bytes from a prior
    // build_jumpdests / evmc2 prepare); otherwise the map is built and owned
    // here. `code`/`msg`/`host`/`ctx`/`prebuilt_analysis` are borrowed and must
    // outlive this state.
    EvmState(const evmc_message* msg,
             const uint8_t* code, size_t codeSize,
             const evmc_host_interface* host,
             evmc_host_context* ctx,
             evmc_revision rev,
             const uint8_t* prebuilt_analysis = nullptr);

    ~EvmState();

    EvmState(const EvmState&) = delete;
    EvmState& operator=(const EvmState&) = delete;
};

}  // namespace zevm

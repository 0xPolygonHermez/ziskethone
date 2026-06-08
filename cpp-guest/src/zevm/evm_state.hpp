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

// All the mutable state of a single call frame. One EvmState is created per
// execute() invocation (top-level call or nested CALL/CREATE) and destroyed
// when the frame returns.
struct EvmState {
    // ----- program counter & code -----
    size_t         pc = 0;
    const uint8_t* code = nullptr;     // borrowed; owned by the caller
    size_t         codeSize = 0;

    // Per-byte JUMPDEST validity map, same length as `code`: analyzedCode[i]
    // == 1 iff `code[i]` is a JUMPDEST opcode that is NOT inside PUSH data.
    // Owned by this state (allocated in the constructor, freed in the dtor).
    uint8_t*       analyzedCode = nullptr;

    // ----- operand stack -----
    // 256-bit words. stackPointer follows the spec's convention: it counts
    // DOWN from kStackLimit (empty) toward 0 (full). A push pre-decrements,
    // a pop post-increments. Number of live items == kStackLimit - stackPointer.
    U256           stack[kStackLimit];
    uint32_t       stackPointer = kStackLimit;   // kStackLimit == empty

    // ----- memory -----
    // Handle into the static EVMMem manager (== this frame's call depth). The
    // frame's bytes live in one of EVMMem's two zones; access goes through
    // EVMMem::readBytes/writeBytes, which use the current top handle. Set by the ctor
    // (createMemory), released by the dtor (destroyMemory).
    int            memHandle = -1;

    // ----- gas -----
    int64_t        gas = 0;

    // ----- evmc plumbing -----
    const evmc_message*           evmcMsg = nullptr;   // borrowed (this frame's message)
    evmc_result*                  evmcResult = nullptr; // result being built for this frame
    evmc_result*                  lastResult = nullptr; // result of the most recent sub-call
    const evmc_host_interface*    host = nullptr;       // borrowed
    evmc_host_context*            context = nullptr;    // borrowed
    evmc_revision                 rev = EVMC_FRONTIER;

    // ----- execution control -----
    // The status the frame will report back to evmc. Handlers set this before
    // halting; the execute() loop turns it into the returned evmc_result.
    evmc_status_code status = EVMC_SUCCESS;

    // Creates and initializes the frame, then runs analyze(). `code`/`msg`/
    // `host`/`ctx` are borrowed and must outlive this state.
    EvmState(const evmc_message* msg,
             const uint8_t* code, size_t codeSize,
             const evmc_host_interface* host,
             evmc_host_context* ctx,
             evmc_revision rev);

    ~EvmState();

    EvmState(const EvmState&) = delete;
    EvmState& operator=(const EvmState&) = delete;

    // Builds analyzedCode: walk the bytecode, mark JUMPDEST (0x5b) bytes, and
    // skip over the immediate data of PUSH1..PUSH32 so a 0x5b that is really
    // push data is never treated as a jump target.
    void analyze();
};

}  // namespace zevm

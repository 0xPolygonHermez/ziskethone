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

// EVM maximum call depth — also the number of preallocated frames (one per live
// depth) and == EVMMem's handle count. run() indexes its static frame array by
// the message's call depth, the same index EVMMem uses for its zones.
inline constexpr size_t kMaxCallDepth = 1024;

// Fill `out` (ceil(codeSize/32) bytes) with the per-32-byte-chunk first-
// instruction map: out[w] is the offset (0..31) of the first real opcode in
// chunk w, or 32 if the chunk is entirely PUSH continuation. With `code` this
// decides valid JUMPDESTs by a short local parse (see EvmState::is_jumpdest).
// Shared by EvmState's own analysis and by the evmc2 `prepare` path, which
// precomputes it once per distinct bytecode.
void mark_first_instruction_in_word(const uint8_t* code, size_t codeSize, uint8_t* out);

// All the mutable state of a single call frame. Frames are preallocated, one per
// call depth, in run()'s static g_frames array and reused across calls — so
// EvmState is a *trivial* type (no in-class member initializers, trivial default
// ctor + dtor) and the array is plain BSS with no global ctor/atexit pass over
// it. reset() initializes every field for a new frame; teardown() releases it.
struct EvmState {
    // ----- program counter & code -----
    size_t         pc;
    const uint8_t* code;               // borrowed; owned by the caller
    size_t         codeSize;

    // First-instruction-per-chunk map (ceil(codeSize/32) bytes): analyzedCode[w]
    // is the offset of chunk w's first opcode, or 32 if none (see
    // mark_first_instruction_in_word). With `code` it decides valid JUMPDESTs
    // (see is_jumpdest). Either borrowed from a precomputed evmc2 analysis or
    // owned (allocated + filled by reset(), freed by teardown()).
    const uint8_t* analyzedCode;
    bool           ownsAnalysis;

    // ----- operand stack -----
    // 256-bit words, each held in big-endian wire form (the 32 memory/storage/
    // PUSH bytes, stored as four little-endian words == byteswap256 of the
    // value). Arithmetic/positional handlers convert to little-endian limbs
    // locally via detail.hpp's ld_le/st_le; everything else touches these BE
    // slots directly. stackPointer follows the spec's convention: it counts DOWN
    // from kStackLimit (empty) toward 0 (full). A push pre-decrements, a pop
    // post-increments. Number of live items == kStackLimit - stackPointer.
    U256           stack[kStackLimit];
    uint32_t       stackPointer;       // kStackLimit == empty

    // ----- memory -----
    // Handle into the static EVMMem manager (== this frame's call depth). The
    // frame's bytes live in one of EVMMem's two zones; access goes through
    // EVMMem::readBytes/writeBytes, which use the current top handle. Set by
    // reset() (createMemory), released by teardown() (destroyMemory); -1 == no
    // live EVMMem frame (the guard that makes teardown idempotent).
    int            memHandle;

    // ----- gas -----
    int64_t        gas;
    // Accumulated gas refund (SSTORE clears, etc.; may go negative). Reported in
    // the frame's evmc_result on success; the host applies the EIP-3529 cap.
    int64_t        gas_refund;

    // ----- evmc plumbing -----
    const evmc_message*           evmcMsg;     // borrowed (this frame's message)
    evmc_result*                  evmcResult;  // result being built for this frame
    evmc_result*                  lastResult;  // result of the most recent sub-call
    const evmc_host_interface*    host;        // borrowed
    evmc_host_context*            context;     // borrowed
    evmc_revision                 rev;

    // ----- output & return data -----
    // RETURN/REVERT set the frame's output region (a window into memory); run()
    // copies it into the evmc_result. output_size == 0 means no output.
    size_t         output_offset;
    size_t         output_size;
    // The most recent sub-call's result (CALL family), whose output_data/
    // output_size back RETURNDATASIZE / RETURNDATACOPY — no copy. A zevm child
    // runs at depth+1, i.e. the *other* EVMMem zone (depth parity), which the
    // parent never writes, so its output is conserved until the parent's next
    // call. Released when superseded or at teardown — which only does work for a
    // precompile's output (heap-owned: malloc'd, release set); a zevm child's
    // output lives in EVMMem and has no release.
    evmc_result    returnDataOwner;

    // ----- execution control -----
    // The status the frame will report back to evmc. Handlers set this before
    // halting; the execute() loop turns it into the returned evmc_result.
    evmc_status_code status;

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

    // (Re)initialize this frame for a new call: sets every field (a reused slot
    // has stale values), borrows or builds the chunk map, and pushes a fresh
    // EVMMem frame. `code`/`msg`/`host`/`ctx`/`prebuilt_analysis` are borrowed and
    // must outlive the frame. When `prebuilt_analysis` is non-null it is borrowed
    // as the chunk map (from a prior evmc2 prepare); else the map is built/owned.
    void reset(const evmc_message* msg,
               const uint8_t* code, size_t codeSize,
               const evmc_host_interface* host,
               evmc_host_context* ctx,
               evmc_revision rev,
               const uint8_t* prebuilt_analysis = nullptr);

    // Release the frame: pop its EVMMem frame, free an owned chunk map, release a
    // held sub-call result. Idempotent (guarded by memHandle).
    void teardown();

    // Trivial default ctor + dtor keep the static g_frames array plain BSS (no
    // global init/atexit pass). The argument ctor is a convenience for
    // stack-allocated frames (host unit tests); they must call teardown().
    EvmState() = default;
    ~EvmState() = default;
    EvmState(const evmc_message* msg,
             const uint8_t* code, size_t codeSize,
             const evmc_host_interface* host,
             evmc_host_context* ctx,
             evmc_revision rev,
             const uint8_t* prebuilt_analysis = nullptr) {
        reset(msg, code, codeSize, host, ctx, rev, prebuilt_analysis);
    }

    EvmState(const EvmState&) = delete;
    EvmState& operator=(const EvmState&) = delete;
};

}  // namespace zevm

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

// The opcode handlers, pulled in as inline headers so the dispatch switch below
// can fold the hot ones directly into the per-fork loop (no out-of-line call, no
// function-pointer table). Each lives in its own zevm::<category>_ops namespace.
#include "instructions/detail.hpp"
#include "instructions/arith.inl.hpp"
#include "instructions/bitwise.inl.hpp"
#include "instructions/keccak.inl.hpp"
#include "instructions/env.inl.hpp"
#include "instructions/memory.inl.hpp"
#include "instructions/storage.inl.hpp"
#include "instructions/control.inl.hpp"
#include "instructions/stack.inl.hpp"
#include "instructions/push.inl.hpp"
#include "instructions/log.inl.hpp"
#include "instructions/system.inl.hpp"

namespace zevm {

namespace {

// zevm's evmc2_pre_execution handle IS the JUMPDEST bitset itself:
// ceil(code_size/64) malloc'd u64 words (see build_jumpdest_bitset), cast
// to/from the opaque handle type — no wrapper struct. Null when code_size == 0
// (nothing to analyze).

// One preallocated frame per call depth, reused across calls (the call stack has
// exactly one live frame per depth). Static (not heap): the trivial EvmState
// makes this plain zeroed BSS. run() reset()s the slot on entry, teardown()s it
// on return. Indexed by msg->depth — the same index EVMMem uses for its zones,
// so the existing depth-limit light-fail keeps it in range.
EvmState g_frames[kMaxCallDepth + 1];  // frames live at depths 0..kMaxCallDepth

// ----- straight-line opcode dispatch -----
//
// One specialized loop per fork (instantiated by run_dispatch below, one per
// distinct opcode set): fetch the opcode at pc and run its inline handler until
// one returns false (halt). This replaces the old function-pointer table — the
// switch lets the compiler inline the hot handlers, and `if constexpr (Rev >= …)`
// gates fork-introduced opcodes at compile time (an absent opcode is undefined,
// exactly like an opcode missing from evmone's revision table).

// op: run the handler; a false return halts the frame.
#define OP(code, ns, fn) \
    case code: if (!ns::fn(s, R)) return; break;
// gated op: present only when the compile-time revision is at/after REV; before
// that the slot is undefined.
#define OPG(code, REV, ns, fn) \
    case code: \
        if constexpr (Rev >= REV) { if (!ns::fn(s, R)) return; break; } \
        else { s.status = EVMC_UNDEFINED_INSTRUCTION; return; }

// Centralized-advance op: the handler leaves pc/top untouched on success; the
// loop advances pc by 1 and the stack top by `sd` (the opcode's net stack-height
// change in slots, e.g. +1 for a 2->1 binary op). Only for ops with a fixed +1
// pc advance and a fixed stack delta (irregular ops — PUSH/JUMP/CALL/… — keep OP
// and manage pc/top themselves).
#define OPS(code, ns, fn, sd) \
    case code: if (!ns::fn(s, R)) return; R.pc += 1; R.top += (sd); break;
#define OPSG(code, REV, ns, fn, sd) \
    case code: \
        if constexpr (Rev >= REV) { if (!ns::fn(s, R)) return; R.pc += 1; R.top += (sd); break; } \
        else { s.status = EVMC_UNDEFINED_INSTRUCTION; return; }

// The fork-specialized loop, operating on register-resident state R (gas / stack
// pointer / pc). always_inline so that, once it folds into dispatch_loop below,
// R is a plain local whose address never escapes — the compiler keeps gas/sp/pc
// in registers across the loop instead of reloading them from EvmState per op.
template <evmc_revision Rev>
[[gnu::always_inline]] inline void dispatch_inner(EvmState& s, Regs& R,
                                                  const uint8_t* code, size_t codeSize) {
    for (;;) {
        // Past the end of code behaves like STOP (opcode 0x00).
        const uint8_t op = R.pc < codeSize ? code[R.pc] : 0x00;
        switch (op) {
            OP(0x00, control_ops, op_stop)
            OPS(0x01, arith_ops, op_add, 1)
            OPS(0x02, arith_ops, op_mul, 1)
            OPS(0x03, arith_ops, op_sub, 1)
            OPS(0x04, arith_ops, op_div, 1)
            OPS(0x05, arith_ops, op_sdiv, 1)
            OPS(0x06, arith_ops, op_mod, 1)
            OPS(0x07, arith_ops, op_smod, 1)
            OPS(0x08, arith_ops, op_addmod, 2)
            OPS(0x09, arith_ops, op_mulmod, 2)
            OPS(0x0a, arith_ops, op_exp, 1)
            OPS(0x0b, arith_ops, op_signextend, 1)
            OPS(0x10, bitwise_ops, op_lt, 1)
            OPS(0x11, bitwise_ops, op_gt, 1)
            OPS(0x12, bitwise_ops, op_slt, 1)
            OPS(0x13, bitwise_ops, op_sgt, 1)
            OPS(0x14, bitwise_ops, op_eq, 1)
            OPS(0x15, bitwise_ops, op_iszero, 0)
            OPS(0x16, bitwise_ops, op_and, 1)
            OPS(0x17, bitwise_ops, op_or, 1)
            OPS(0x18, bitwise_ops, op_xor, 1)
            OPS(0x19, bitwise_ops, op_not, 0)
            OPS(0x1a, bitwise_ops, op_byte, 1)
            OPSG(0x1b, EVMC_CONSTANTINOPLE, bitwise_ops, op_shl, 1)
            OPSG(0x1c, EVMC_CONSTANTINOPLE, bitwise_ops, op_shr, 1)
            OPSG(0x1d, EVMC_CONSTANTINOPLE, bitwise_ops, op_sar, 1)
            OPSG(0x1e, EVMC_OSAKA, bitwise_ops, op_clz, 0)
            OPS(0x20, keccak_ops, op_keccak256, 1)
            OPS(0x30, env_ops, op_address, -1)
            OPS(0x31, env_ops, op_balance, 0)
            OPS(0x32, env_ops, op_origin, -1)
            OPS(0x33, env_ops, op_caller, -1)
            OPS(0x34, env_ops, op_callvalue, -1)
            OPS(0x35, env_ops, op_calldataload, 0)
            OPS(0x36, env_ops, op_calldatasize, -1)
            OPS(0x37, env_ops, op_calldatacopy, 3)
            OPS(0x38, env_ops, op_codesize, -1)
            OPS(0x39, env_ops, op_codecopy, 3)
            OPS(0x3a, env_ops, op_gasprice, -1)
            OPS(0x3b, env_ops, op_extcodesize, 0)
            OPS(0x3c, env_ops, op_extcodecopy, 4)
            OPSG(0x3d, EVMC_BYZANTIUM, system_ops, op_returndatasize, -1)
            OPSG(0x3e, EVMC_BYZANTIUM, system_ops, op_returndatacopy, 3)
            OPSG(0x3f, EVMC_CONSTANTINOPLE, env_ops, op_extcodehash, 0)
            OPS(0x40, env_ops, op_blockhash, 0)
            OPS(0x41, env_ops, op_coinbase, -1)
            OPS(0x42, env_ops, op_timestamp, -1)
            OPS(0x43, env_ops, op_number, -1)
            OPS(0x44, env_ops, op_prevrandao, -1)
            OPS(0x45, env_ops, op_gaslimit, -1)
            OPSG(0x46, EVMC_ISTANBUL, env_ops, op_chainid, -1)
            OPSG(0x47, EVMC_ISTANBUL, env_ops, op_selfbalance, -1)
            OPSG(0x48, EVMC_LONDON, env_ops, op_basefee, -1)
            OPSG(0x49, EVMC_CANCUN, env_ops, op_blobhash, 0)
            OPSG(0x4a, EVMC_CANCUN, env_ops, op_blobbasefee, -1)
            OPS(0x50, control_ops, op_pop, 1)
            OPS(0x51, memory_ops, op_mload, 0)
            OPS(0x52, memory_ops, op_mstore, 2)
            OPS(0x53, memory_ops, op_mstore8, 2)
            OPS(0x54, storage_ops, op_sload, 0)
            OPS(0x55, storage_ops, op_sstore, 2)
            OP(0x56, control_ops, op_jump)
            OP(0x57, control_ops, op_jumpi)
            OPS(0x58, control_ops, op_pc, -1)
            OPS(0x59, memory_ops, op_msize, -1)
            OPS(0x5a, control_ops, op_gas, -1)
            OPS(0x5b, control_ops, op_jumpdest, 0)
            OPSG(0x5c, EVMC_CANCUN, storage_ops, op_tload, 0)
            OPSG(0x5d, EVMC_CANCUN, storage_ops, op_tstore, 2)
            OPSG(0x5e, EVMC_CANCUN, memory_ops, op_mcopy, 3)
            OPSG(0x5f, EVMC_SHANGHAI, push_ops, op_push0, -1)
            OP(0x60, push_ops, op_push1)
            OP(0x61, push_ops, op_push2)
            OP(0x62, push_ops, op_push3)
            OP(0x63, push_ops, op_push4)
            OP(0x64, push_ops, op_push5)
            OP(0x65, push_ops, op_push6)
            OP(0x66, push_ops, op_push7)
            OP(0x67, push_ops, op_push8)
            OP(0x68, push_ops, op_push9)
            OP(0x69, push_ops, op_push10)
            OP(0x6a, push_ops, op_push11)
            OP(0x6b, push_ops, op_push12)
            OP(0x6c, push_ops, op_push13)
            OP(0x6d, push_ops, op_push14)
            OP(0x6e, push_ops, op_push15)
            OP(0x6f, push_ops, op_push16)
            OP(0x70, push_ops, op_push17)
            OP(0x71, push_ops, op_push18)
            OP(0x72, push_ops, op_push19)
            OP(0x73, push_ops, op_push20)
            OP(0x74, push_ops, op_push21)
            OP(0x75, push_ops, op_push22)
            OP(0x76, push_ops, op_push23)
            OP(0x77, push_ops, op_push24)
            OP(0x78, push_ops, op_push25)
            OP(0x79, push_ops, op_push26)
            OP(0x7a, push_ops, op_push27)
            OP(0x7b, push_ops, op_push28)
            OP(0x7c, push_ops, op_push29)
            OP(0x7d, push_ops, op_push30)
            OP(0x7e, push_ops, op_push31)
            OP(0x7f, push_ops, op_push32)
            OPS(0x80, stack_ops, op_dup1, -1)
            OPS(0x81, stack_ops, op_dup2, -1)
            OPS(0x82, stack_ops, op_dup3, -1)
            OPS(0x83, stack_ops, op_dup4, -1)
            OPS(0x84, stack_ops, op_dup5, -1)
            OPS(0x85, stack_ops, op_dup6, -1)
            OPS(0x86, stack_ops, op_dup7, -1)
            OPS(0x87, stack_ops, op_dup8, -1)
            OPS(0x88, stack_ops, op_dup9, -1)
            OPS(0x89, stack_ops, op_dup10, -1)
            OPS(0x8a, stack_ops, op_dup11, -1)
            OPS(0x8b, stack_ops, op_dup12, -1)
            OPS(0x8c, stack_ops, op_dup13, -1)
            OPS(0x8d, stack_ops, op_dup14, -1)
            OPS(0x8e, stack_ops, op_dup15, -1)
            OPS(0x8f, stack_ops, op_dup16, -1)
            OPS(0x90, stack_ops, op_swap1, 0)
            OPS(0x91, stack_ops, op_swap2, 0)
            OPS(0x92, stack_ops, op_swap3, 0)
            OPS(0x93, stack_ops, op_swap4, 0)
            OPS(0x94, stack_ops, op_swap5, 0)
            OPS(0x95, stack_ops, op_swap6, 0)
            OPS(0x96, stack_ops, op_swap7, 0)
            OPS(0x97, stack_ops, op_swap8, 0)
            OPS(0x98, stack_ops, op_swap9, 0)
            OPS(0x99, stack_ops, op_swap10, 0)
            OPS(0x9a, stack_ops, op_swap11, 0)
            OPS(0x9b, stack_ops, op_swap12, 0)
            OPS(0x9c, stack_ops, op_swap13, 0)
            OPS(0x9d, stack_ops, op_swap14, 0)
            OPS(0x9e, stack_ops, op_swap15, 0)
            OPS(0x9f, stack_ops, op_swap16, 0)
            OP(0xa0, log_ops, op_log0)
            OP(0xa1, log_ops, op_log1)
            OP(0xa2, log_ops, op_log2)
            OP(0xa3, log_ops, op_log3)
            OP(0xa4, log_ops, op_log4)
            OP(0xf0, system_ops, op_create)
            OP(0xf1, system_ops, op_call)
            OP(0xf2, system_ops, op_callcode)
            OP(0xf3, system_ops, op_return)
            OPG(0xf4, EVMC_HOMESTEAD, system_ops, op_delegatecall)
            OPG(0xf5, EVMC_CONSTANTINOPLE, system_ops, op_create2)
            OPG(0xfa, EVMC_BYZANTIUM, system_ops, op_staticcall)
            OPG(0xfd, EVMC_BYZANTIUM, system_ops, op_revert)
            OP(0xfe, system_ops, op_invalid)
            OP(0xff, system_ops, op_selfdestruct)
            default: s.status = EVMC_UNDEFINED_INSTRUCTION; return;
        }
    }
}
#undef OP
#undef OPG

// Seed the register-resident state from EvmState, run the fork loop to a halt,
// then write the final state back (run() reads EvmState::gas for the result).
template <evmc_revision Rev>
void dispatch_loop(EvmState& s) {
    Regs R{s.gas, s.stack + s.stackPointer, s.pc, s.stack + kStackLimit};
    dispatch_inner<Rev>(s, R, s.code, s.codeSize);
    s.gas = R.gas;
    s.stackPointer = static_cast<size_t>(R.top - s.stack);
    s.pc = R.pc;
}

// Pick the specialized loop for `rev`. Revisions that share an opcode set reuse
// one instantiation (the fork-dependent *gas* logic inside handlers reads the
// runtime EvmState::rev, so only the opcode availability needs the compile-time
// revision). One loop per distinct fork opcode set: Frontier, Homestead,
// Byzantium, Constantinople, Istanbul, London, Shanghai, Cancun, Osaka.
void run_dispatch(evmc_revision rev, EvmState& s) {
    switch (rev) {
        case EVMC_FRONTIER:                                  dispatch_loop<EVMC_FRONTIER>(s);       break;
        case EVMC_HOMESTEAD:
        case EVMC_TANGERINE_WHISTLE:
        case EVMC_SPURIOUS_DRAGON:                           dispatch_loop<EVMC_HOMESTEAD>(s);      break;
        case EVMC_BYZANTIUM:                                 dispatch_loop<EVMC_BYZANTIUM>(s);      break;
        case EVMC_CONSTANTINOPLE:
        case EVMC_PETERSBURG:                                dispatch_loop<EVMC_CONSTANTINOPLE>(s); break;
        case EVMC_ISTANBUL:
        case EVMC_BERLIN:                                    dispatch_loop<EVMC_ISTANBUL>(s);       break;
        case EVMC_LONDON:
        case EVMC_PARIS:                                     dispatch_loop<EVMC_LONDON>(s);         break;
        case EVMC_SHANGHAI:                                  dispatch_loop<EVMC_SHANGHAI>(s);       break;
        case EVMC_CANCUN:
        case EVMC_PRAGUE:                                    dispatch_loop<EVMC_CANCUN>(s);         break;
        case EVMC_OSAKA:
        default:                                             dispatch_loop<EVMC_OSAKA>(s);          break;
    }
}

// Run one frame to completion and build its evmc_result. `prebuilt` is an
// optional JUMPDEST bitset borrowed for this frame; when null, EvmState builds
// its own.
evmc_result run(const evmc_host_interface* host, evmc_host_context* context,
                evmc_revision rev, const evmc_message* msg,
                const uint8_t* code, size_t code_size,
                const uint64_t* prebuilt) noexcept {
    // Use this depth's preallocated frame and reset it for the call. EvmState is
    // large (~34 KB — it embeds the 1024-entry operand stack); the static array
    // keeps it off both the native C++ stack (a nested CALL re-enters run()
    // recursively, so on-stack frames would overflow the thread stack near max
    // depth) and the heap (no per-frame allocation).
    EvmState& state = g_frames[msg->depth];
    state.reset(msg, code, code_size, host, context, rev, prebuilt);

    // Run this revision's specialized straight-line dispatch loop to completion
    // (fork-gated opcodes resolved at compile time; no runtime table).
    run_dispatch(rev, state);

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
    // malloc (not calloc): build_jumpdest_bitset writes every word.
    const size_t nWords = (code_size + 63) / 64;
    auto* bitset = static_cast<uint64_t*>(std::malloc(nWords * sizeof(uint64_t)));
    build_jumpdest_bitset(code, code_size, bitset);
    return reinterpret_cast<evmc2_pre_execution*>(bitset);
}

void w_release(evmc_vm* /*vm*/, evmc2_pre_execution* pre) noexcept {
    std::free(pre);
}

evmc_result w_execute2(evmc_vm* /*vm*/, const evmc_host_interface* host,
                       evmc_host_context* context, evmc_revision rev,
                       const evmc_message* msg, const uint8_t* code,
                       size_t code_size, evmc2_pre_execution* pre) noexcept {
    return run(host, context, rev, msg, code, code_size,
               reinterpret_cast<const uint64_t*>(pre));
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

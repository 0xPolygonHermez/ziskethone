// instructions.cpp — MOCK opcode handlers + the dispatch table.
//
// SCAFFOLDING ONLY. None of these implement real EVM semantics yet; they exist
// so the dispatch table, the execute() loop, and the evmc result plumbing can
// be wired up and compiled end to end. As real opcodes land, replace the mock
// bodies one at a time. Arithmetic / bitwise opcodes (ADD, MUL, AND, ...) are
// the prime candidates for routing through the ZisK-accelerated zeg::bi backend
// (cpp-guest/zisk/bigint/backend.hpp), since the stack words are already in its
// little-endian uint64_t[4] layout.

#include "instructions.hpp"

#include <algorithm>  // std::min for the PUSH zero-pad fallback
#include <cstring>    // memcpy for the unaligned PUSH word loads

#include "bigint/backend.hpp"  // zeg::bi::add256 — ZisK-accelerated 256-bit add

// libgcc 64-bit byte swap. On the ZisK target (rv64ima, no Zbb) there is no
// hardware byteswap instruction, so this resolves to the soft implementation in
// zisk/compiler_rt.cpp; on the host it comes from the compiler-rt builtins.
extern "C" uint64_t __bswapdi2(uint64_t);

namespace zevm {

namespace {

// EVM gas cost tiers (subset; grows as opcodes land).
constexpr int64_t GAS_VERYLOW = 3;   // ADD, SUB, NOT, PUSH, ...

// Number of live operands on the stack. stackPointer counts DOWN from
// kStackLimit (empty) toward 0 (full), so depth == kStackLimit - stackPointer.
inline size_t stack_depth(const EvmState& s) {
    return kStackLimit - s.stackPointer;
}

// Unaligned 64-bit load from code.
inline uint64_t load_u64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

// Default for every opcode without a dedicated handler. Halts the frame with a
// failure status so unknown/unimplemented opcodes are observable rather than
// silently skipped.
bool op_unimplemented(EvmState& s) {
    s.status = EVMC_UNDEFINED_INSTRUCTION;
    return false;  // stop
}

// 0x00 STOP — halt successfully.
bool op_stop(EvmState& s) {
    s.status = EVMC_SUCCESS;
    return false;  // stop
}

// 0xfe INVALID — designated invalid opcode; consumes all gas (real semantics
// will zero gas), halts with failure.
bool op_invalid(EvmState& s) {
    s.status = EVMC_INVALID_INSTRUCTION;
    return false;  // stop
}

// 0x01 ADD — pop a and b, push (a + b) mod 2^256.
bool op_add(EvmState& s) {
    // Charge gas first (matches evmone/revm ordering: gas before stack work).
    if (s.gas < GAS_VERYLOW) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    s.gas -= GAS_VERYLOW;

    // Needs two operands.
    if (stack_depth(s) < 2) {
        s.status = EVMC_STACK_UNDERFLOW;
        return false;
    }

    // Top is stack[stackPointer], the next item is stack[stackPointer + 1].
    // After popping both and pushing the result the new top lands in the second
    // slot, so add in place straight into it — no temporary, no copy. add256
    // reads both inputs before writing, so output aliasing input `b` is fine; it
    // does the full 256-bit add and returns the carry-out, which we drop to wrap
    // mod 2^256.
    const U256& a = s.stack[s.stackPointer];
    U256&       b = s.stack[s.stackPointer + 1];
    zeg::bi::add256(a.limbs, b.limbs, /*cin=*/0, b.limbs);  // b = a + b (mod 2^256)

    ++s.stackPointer;  // net: pop two, push one (result already in place)
    ++s.pc;
    return true;
}

// 0x5b JUMPDEST — valid jump target marker; a no-op that just advances pc.
bool op_jumpdest(EvmState& s) {
    ++s.pc;
    return true;
}

// 0x60..0x7e PUSH1..PUSH31 — push the next n code bytes as a big-endian word,
// right-aligned in the 256-bit stack word (high bytes zero). Written out
// explicitly (no shared helper). The n big-endian bytes end at code[pc+n] (the
// value's least-significant byte), so each limb's eight bytes are the 64-bit
// word ending there, byte-swapped (__bswapdi2): full limbs are copied whole, the
// one partial limb is masked to its valid low bytes, and limbs entirely above
// the value are 0. The fast path requires every read to be in-bounds; a PUSH
// near the start or end of code (where the right-aligned reads would fall off
// the unpadded buffer) falls back to a zero-padded build.

bool op_push1(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 1 >= 7 && s.pc + 2 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 2;
        w.limbs[0] = __bswapdi2(load_u64(end - 8)) & 0xffULL;
        w.limbs[1] = 0; w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(1, s.codeSize - pc1) : 0;
        std::memcpy(be + 31, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 2;
    return true;
}

bool op_push2(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 2 >= 7 && s.pc + 3 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 3;
        w.limbs[0] = __bswapdi2(load_u64(end - 8)) & 0xffffULL;
        w.limbs[1] = 0; w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(2, s.codeSize - pc1) : 0;
        std::memcpy(be + 30, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 3;
    return true;
}

bool op_push3(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 3 >= 7 && s.pc + 4 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 4;
        w.limbs[0] = __bswapdi2(load_u64(end - 8)) & 0xffffffULL;
        w.limbs[1] = 0; w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(3, s.codeSize - pc1) : 0;
        std::memcpy(be + 29, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 4;
    return true;
}

bool op_push4(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 4 >= 7 && s.pc + 5 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 5;
        w.limbs[0] = __bswapdi2(load_u64(end - 8)) & 0xffffffffULL;
        w.limbs[1] = 0; w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(4, s.codeSize - pc1) : 0;
        std::memcpy(be + 28, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 5;
    return true;
}

bool op_push5(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 5 >= 7 && s.pc + 6 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 6;
        w.limbs[0] = __bswapdi2(load_u64(end - 8)) & 0xffffffffffULL;
        w.limbs[1] = 0; w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(5, s.codeSize - pc1) : 0;
        std::memcpy(be + 27, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 6;
    return true;
}

bool op_push6(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 6 >= 7 && s.pc + 7 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 7;
        w.limbs[0] = __bswapdi2(load_u64(end - 8)) & 0xffffffffffffULL;
        w.limbs[1] = 0; w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(6, s.codeSize - pc1) : 0;
        std::memcpy(be + 26, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 7;
    return true;
}

bool op_push7(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 8 <= s.codeSize) {                       // pc + REM(7) >= 7 is always true
        const uint8_t* end = s.code + s.pc + 8;
        w.limbs[0] = __bswapdi2(load_u64(end - 8)) & 0xffffffffffffffULL;
        w.limbs[1] = 0; w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(7, s.codeSize - pc1) : 0;
        std::memcpy(be + 25, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 8;
    return true;
}

bool op_push8(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 9 <= s.codeSize) {                       // one full limb, no partial
        const uint8_t* end = s.code + s.pc + 9;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = 0; w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(8, s.codeSize - pc1) : 0;
        std::memcpy(be + 24, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 9;
    return true;
}

bool op_push9(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 1 >= 7 && s.pc + 10 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 10;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16)) & 0xffULL;
        w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(9, s.codeSize - pc1) : 0;
        std::memcpy(be + 23, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 10;
    return true;
}

bool op_push10(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 2 >= 7 && s.pc + 11 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 11;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16)) & 0xffffULL;
        w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(10, s.codeSize - pc1) : 0;
        std::memcpy(be + 22, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 11;
    return true;
}

bool op_push11(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 3 >= 7 && s.pc + 12 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 12;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16)) & 0xffffffULL;
        w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(11, s.codeSize - pc1) : 0;
        std::memcpy(be + 21, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 12;
    return true;
}

bool op_push12(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 4 >= 7 && s.pc + 13 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 13;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16)) & 0xffffffffULL;
        w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(12, s.codeSize - pc1) : 0;
        std::memcpy(be + 20, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 13;
    return true;
}

bool op_push13(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 5 >= 7 && s.pc + 14 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 14;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16)) & 0xffffffffffULL;
        w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(13, s.codeSize - pc1) : 0;
        std::memcpy(be + 19, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 14;
    return true;
}

bool op_push14(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 6 >= 7 && s.pc + 15 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 15;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16)) & 0xffffffffffffULL;
        w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(14, s.codeSize - pc1) : 0;
        std::memcpy(be + 18, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 15;
    return true;
}

bool op_push15(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 16 <= s.codeSize) {                      // pc + REM(7) >= 7 is always true
        const uint8_t* end = s.code + s.pc + 16;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16)) & 0xffffffffffffffULL;
        w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(15, s.codeSize - pc1) : 0;
        std::memcpy(be + 17, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 16;
    return true;
}

bool op_push16(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 17 <= s.codeSize) {                      // two full limbs, no partial
        const uint8_t* end = s.code + s.pc + 17;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = 0; w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(16, s.codeSize - pc1) : 0;
        std::memcpy(be + 16, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 17;
    return true;
}

bool op_push17(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 1 >= 7 && s.pc + 18 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 18;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24)) & 0xffULL;
        w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(17, s.codeSize - pc1) : 0;
        std::memcpy(be + 15, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 18;
    return true;
}

bool op_push18(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 2 >= 7 && s.pc + 19 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 19;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24)) & 0xffffULL;
        w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(18, s.codeSize - pc1) : 0;
        std::memcpy(be + 14, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 19;
    return true;
}

bool op_push19(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 3 >= 7 && s.pc + 20 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 20;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24)) & 0xffffffULL;
        w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(19, s.codeSize - pc1) : 0;
        std::memcpy(be + 13, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 20;
    return true;
}

bool op_push20(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 4 >= 7 && s.pc + 21 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 21;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24)) & 0xffffffffULL;
        w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(20, s.codeSize - pc1) : 0;
        std::memcpy(be + 12, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 21;
    return true;
}

bool op_push21(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 5 >= 7 && s.pc + 22 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 22;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24)) & 0xffffffffffULL;
        w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(21, s.codeSize - pc1) : 0;
        std::memcpy(be + 11, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 22;
    return true;
}

bool op_push22(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 6 >= 7 && s.pc + 23 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 23;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24)) & 0xffffffffffffULL;
        w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(22, s.codeSize - pc1) : 0;
        std::memcpy(be + 10, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 23;
    return true;
}

bool op_push23(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 24 <= s.codeSize) {                      // pc + REM(7) >= 7 is always true
        const uint8_t* end = s.code + s.pc + 24;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24)) & 0xffffffffffffffULL;
        w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(23, s.codeSize - pc1) : 0;
        std::memcpy(be + 9, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 24;
    return true;
}

bool op_push24(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 25 <= s.codeSize) {                      // three full limbs, no partial
        const uint8_t* end = s.code + s.pc + 25;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24));
        w.limbs[3] = 0;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(24, s.codeSize - pc1) : 0;
        std::memcpy(be + 8, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 25;
    return true;
}

bool op_push25(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 1 >= 7 && s.pc + 26 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 26;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24));
        w.limbs[3] = __bswapdi2(load_u64(end - 32)) & 0xffULL;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(25, s.codeSize - pc1) : 0;
        std::memcpy(be + 7, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 26;
    return true;
}

bool op_push26(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 2 >= 7 && s.pc + 27 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 27;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24));
        w.limbs[3] = __bswapdi2(load_u64(end - 32)) & 0xffffULL;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(26, s.codeSize - pc1) : 0;
        std::memcpy(be + 6, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 27;
    return true;
}

bool op_push27(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 3 >= 7 && s.pc + 28 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 28;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24));
        w.limbs[3] = __bswapdi2(load_u64(end - 32)) & 0xffffffULL;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(27, s.codeSize - pc1) : 0;
        std::memcpy(be + 5, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 28;
    return true;
}

bool op_push28(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 4 >= 7 && s.pc + 29 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 29;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24));
        w.limbs[3] = __bswapdi2(load_u64(end - 32)) & 0xffffffffULL;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(28, s.codeSize - pc1) : 0;
        std::memcpy(be + 4, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 29;
    return true;
}

bool op_push29(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 5 >= 7 && s.pc + 30 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 30;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24));
        w.limbs[3] = __bswapdi2(load_u64(end - 32)) & 0xffffffffffULL;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(29, s.codeSize - pc1) : 0;
        std::memcpy(be + 3, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 30;
    return true;
}

bool op_push30(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 6 >= 7 && s.pc + 31 <= s.codeSize) {
        const uint8_t* end = s.code + s.pc + 31;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24));
        w.limbs[3] = __bswapdi2(load_u64(end - 32)) & 0xffffffffffffULL;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(30, s.codeSize - pc1) : 0;
        std::memcpy(be + 2, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 31;
    return true;
}

bool op_push31(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    if (s.pc + 32 <= s.codeSize) {                      // pc + REM(7) >= 7 is always true
        const uint8_t* end = s.code + s.pc + 32;
        w.limbs[0] = __bswapdi2(load_u64(end - 8));
        w.limbs[1] = __bswapdi2(load_u64(end - 16));
        w.limbs[2] = __bswapdi2(load_u64(end - 24));
        w.limbs[3] = __bswapdi2(load_u64(end - 32)) & 0xffffffffffffffULL;
    } else {
        uint8_t be[32] = {};
        const size_t pc1 = s.pc + 1;
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(31, s.codeSize - pc1) : 0;
        std::memcpy(be + 1, s.code + pc1, avail);
        w = u256_from_be(be);
    }
    s.pc += 32;
    return true;
}

// 0x7f PUSH32 — push the next 32 code bytes as a big-endian word.
bool op_push32(EvmState& s) {
    if (s.gas < GAS_VERYLOW) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    s.gas -= GAS_VERYLOW;

    // Pushing onto a full (1024-item) stack overflows.
    if (stack_depth(s) >= kStackLimit) {
        s.status = EVMC_STACK_OVERFLOW;
        return false;
    }

    // The 32 immediate bytes follow the opcode, big-endian. The stack word is
    // little-endian uint64_t[4], so each 8-byte group is byte-swapped into a
    // limb (limb[3] is the most significant). When all 32 bytes are present we
    // read them as four 64-bit words and write the swapped limbs straight into
    // the stack slot — no temporary, no byte loop.
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    const uint8_t* p = s.code + s.pc + 1;
    if (s.pc + 32 < s.codeSize) {
        w.limbs[3] = __bswapdi2(load_u64(p +  0));
        w.limbs[2] = __bswapdi2(load_u64(p +  8));
        w.limbs[1] = __bswapdi2(load_u64(p + 16));
        w.limbs[0] = __bswapdi2(load_u64(p + 24));
    } else {
        // PUSH data runs past the end of code (rare): zero-pad the missing
        // low-order bytes. `code` isn't padded, so the blind 64-bit reads above
        // would be out of bounds here.
        uint8_t be[32] = {};
        std::memcpy(be, p, s.codeSize - (s.pc + 1));
        w = u256_from_be(be);
    }

    s.pc += 33;  // opcode + 32 immediate bytes
    return true;
}

// Build the full 256-entry table: default every slot to op_unimplemented, then
// slot in the handlers we have. Done at static-init time via a constexpr
// builder so the array is genuinely const with no designated-initializer
// extensions.
constexpr InstrTable build_table() {
    InstrTable t{};
    for (auto& fn : t)
        fn = &op_unimplemented;

    t[0x00] = &op_stop;
    t[0x01] = &op_add;
    t[0x5b] = &op_jumpdest;
    t[0x60] = &op_push1;   t[0x61] = &op_push2;   t[0x62] = &op_push3;
    t[0x63] = &op_push4;   t[0x64] = &op_push5;   t[0x65] = &op_push6;
    t[0x66] = &op_push7;   t[0x67] = &op_push8;   t[0x68] = &op_push9;
    t[0x69] = &op_push10;  t[0x6a] = &op_push11;  t[0x6b] = &op_push12;
    t[0x6c] = &op_push13;  t[0x6d] = &op_push14;  t[0x6e] = &op_push15;
    t[0x6f] = &op_push16;  t[0x70] = &op_push17;  t[0x71] = &op_push18;
    t[0x72] = &op_push19;  t[0x73] = &op_push20;  t[0x74] = &op_push21;
    t[0x75] = &op_push22;  t[0x76] = &op_push23;  t[0x77] = &op_push24;
    t[0x78] = &op_push25;  t[0x79] = &op_push26;  t[0x7a] = &op_push27;
    t[0x7b] = &op_push28;  t[0x7c] = &op_push29;  t[0x7d] = &op_push30;
    t[0x7e] = &op_push31;  t[0x7f] = &op_push32;
    t[0xfe] = &op_invalid;

    return t;
}

}  // namespace

const InstrTable instruction_table = build_table();

}  // namespace zevm

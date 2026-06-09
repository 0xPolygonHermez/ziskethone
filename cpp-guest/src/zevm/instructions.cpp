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

#include <cstring>  // memcpy for the unaligned PUSH word loads

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
    t[0x7f] = &op_push32;
    t[0xfe] = &op_invalid;

    return t;
}

}  // namespace

const InstrTable instruction_table = build_table();

}  // namespace zevm

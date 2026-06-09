// push.cpp — PUSH1..PUSH32 (opcodes 0x60..0x7f).
//
// Lazy endianness: a PUSH value is left in big-endian form. The n immediate
// bytes are big-endian and right-aligned in the 256-bit word, so the word's
// memory bytes are [ (32-n) zero bytes ][ the n code bytes ] — exactly the BE
// stack representation (the wire bytes as four little-endian limbs). We write
// them straight in (no byteswap, no masks) and tag the entry BE; conversion to
// LE is deferred until an arithmetic/comparison op consumes it. A PUSH whose
// data runs past the end of code zero-pads the missing low-order bytes (avail).
// See instructions/detail.hpp / EvmState::stackBE.

#include "detail.hpp"

namespace zevm {

namespace {

// 0x60 PUSH1.
bool op_push1(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(1, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 1), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 1 + 1;
    return true;
}

// 0x61 PUSH2.
bool op_push2(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(2, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 2), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 2 + 1;
    return true;
}

// 0x62 PUSH3.
bool op_push3(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(3, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 3), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 3 + 1;
    return true;
}

// 0x63 PUSH4.
bool op_push4(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(4, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 4), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 4 + 1;
    return true;
}

// 0x64 PUSH5.
bool op_push5(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(5, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 5), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 5 + 1;
    return true;
}

// 0x65 PUSH6.
bool op_push6(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(6, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 6), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 6 + 1;
    return true;
}

// 0x66 PUSH7.
bool op_push7(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(7, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 7), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 7 + 1;
    return true;
}

// 0x67 PUSH8.
bool op_push8(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(8, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 8), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 8 + 1;
    return true;
}

// 0x68 PUSH9.
bool op_push9(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(9, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 9), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 9 + 1;
    return true;
}

// 0x69 PUSH10.
bool op_push10(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(10, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 10), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 10 + 1;
    return true;
}

// 0x6a PUSH11.
bool op_push11(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(11, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 11), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 11 + 1;
    return true;
}

// 0x6b PUSH12.
bool op_push12(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(12, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 12), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 12 + 1;
    return true;
}

// 0x6c PUSH13.
bool op_push13(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(13, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 13), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 13 + 1;
    return true;
}

// 0x6d PUSH14.
bool op_push14(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(14, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 14), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 14 + 1;
    return true;
}

// 0x6e PUSH15.
bool op_push15(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(15, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 15), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 15 + 1;
    return true;
}

// 0x6f PUSH16.
bool op_push16(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(16, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 16), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 16 + 1;
    return true;
}

// 0x70 PUSH17.
bool op_push17(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(17, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 17), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 17 + 1;
    return true;
}

// 0x71 PUSH18.
bool op_push18(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(18, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 18), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 18 + 1;
    return true;
}

// 0x72 PUSH19.
bool op_push19(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(19, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 19), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 19 + 1;
    return true;
}

// 0x73 PUSH20.
bool op_push20(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(20, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 20), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 20 + 1;
    return true;
}

// 0x74 PUSH21.
bool op_push21(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(21, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 21), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 21 + 1;
    return true;
}

// 0x75 PUSH22.
bool op_push22(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(22, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 22), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 22 + 1;
    return true;
}

// 0x76 PUSH23.
bool op_push23(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(23, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 23), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 23 + 1;
    return true;
}

// 0x77 PUSH24.
bool op_push24(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(24, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 24), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 24 + 1;
    return true;
}

// 0x78 PUSH25.
bool op_push25(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(25, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 25), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 25 + 1;
    return true;
}

// 0x79 PUSH26.
bool op_push26(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(26, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 26), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 26 + 1;
    return true;
}

// 0x7a PUSH27.
bool op_push27(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(27, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 27), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 27 + 1;
    return true;
}

// 0x7b PUSH28.
bool op_push28(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(28, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 28), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 28 + 1;
    return true;
}

// 0x7c PUSH29.
bool op_push29(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(29, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 29), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 29 + 1;
    return true;
}

// 0x7d PUSH30.
bool op_push30(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(30, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 30), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 30 + 1;
    return true;
}

// 0x7e PUSH31.
bool op_push31(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(31, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 31), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 31 + 1;
    return true;
}

// 0x7f PUSH32.
bool op_push32(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w = U256{};
    const size_t pc1 = s.pc + 1;
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(32, s.codeSize - pc1) : 0;
    std::memcpy(reinterpret_cast<uint8_t*>(&w) + (32 - 32), s.code + pc1, avail);
    s.stackBE[s.stackPointer] = kBE;
    s.pc += 32 + 1;
    return true;
}

}  // namespace

void register_push(InstrTable& t) {
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
}

}  // namespace zevm

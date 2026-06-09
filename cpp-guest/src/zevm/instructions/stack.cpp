// stack.cpp — stack-shuffling opcodes: DUP1..DUP16 (0x80..0x8f) and
// SWAP1..SWAP16 (0x90..0x9f). POP lives in control.cpp.
//
// DUPn copies the n-th item from the top onto the top (depth + 1); SWAPn swaps
// the top with the (n+1)-th item (depth unchanged). Each costs GAS_VERYLOW. The
// stack grows downward: the top is stack[stackPointer], the i-th-from-top is
// stack[stackPointer + i], and depth == kStackLimit - stackPointer. Both move the
// value and its endianness flag (stackBE) together — no conversion.

#include "detail.hpp"

namespace zevm {

namespace {

// 0x80 DUP1 — duplicate the 1st-from-top item.
bool op_dup1(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 1];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 1];
    ++s.pc;
    return true;
}

// 0x81 DUP2 — duplicate the 2nd-from-top item.
bool op_dup2(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 2];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 2];
    ++s.pc;
    return true;
}

// 0x82 DUP3 — duplicate the 3rd-from-top item.
bool op_dup3(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 3) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 3];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 3];
    ++s.pc;
    return true;
}

// 0x83 DUP4 — duplicate the 4th-from-top item.
bool op_dup4(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 4) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 4];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 4];
    ++s.pc;
    return true;
}

// 0x84 DUP5 — duplicate the 5th-from-top item.
bool op_dup5(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 5) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 5];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 5];
    ++s.pc;
    return true;
}

// 0x85 DUP6 — duplicate the 6th-from-top item.
bool op_dup6(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 6) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 6];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 6];
    ++s.pc;
    return true;
}

// 0x86 DUP7 — duplicate the 7th-from-top item.
bool op_dup7(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 7) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 7];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 7];
    ++s.pc;
    return true;
}

// 0x87 DUP8 — duplicate the 8th-from-top item.
bool op_dup8(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 8) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 8];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 8];
    ++s.pc;
    return true;
}

// 0x88 DUP9 — duplicate the 9th-from-top item.
bool op_dup9(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 9) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 9];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 9];
    ++s.pc;
    return true;
}

// 0x89 DUP10 — duplicate the 10th-from-top item.
bool op_dup10(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 10) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 10];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 10];
    ++s.pc;
    return true;
}

// 0x8a DUP11 — duplicate the 11th-from-top item.
bool op_dup11(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 11) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 11];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 11];
    ++s.pc;
    return true;
}

// 0x8b DUP12 — duplicate the 12th-from-top item.
bool op_dup12(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 12) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 12];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 12];
    ++s.pc;
    return true;
}

// 0x8c DUP13 — duplicate the 13th-from-top item.
bool op_dup13(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 13) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 13];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 13];
    ++s.pc;
    return true;
}

// 0x8d DUP14 — duplicate the 14th-from-top item.
bool op_dup14(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 14) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 14];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 14];
    ++s.pc;
    return true;
}

// 0x8e DUP15 — duplicate the 15th-from-top item.
bool op_dup15(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 15) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 15];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 15];
    ++s.pc;
    return true;
}

// 0x8f DUP16 — duplicate the 16th-from-top item.
bool op_dup16(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 16) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer]   = s.stack[s.stackPointer + 16];
    s.stackBE[s.stackPointer] = s.stackBE[s.stackPointer + 16];
    ++s.pc;
    return true;
}

// 0x90 SWAP1 — swap the top with the 2-th item.
bool op_swap1(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 1];
    s.stack[s.stackPointer + 1] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 1];
    s.stackBE[s.stackPointer + 1] = tf;
    ++s.pc;
    return true;
}

// 0x91 SWAP2 — swap the top with the 3-th item.
bool op_swap2(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 3) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 2];
    s.stack[s.stackPointer + 2] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 2];
    s.stackBE[s.stackPointer + 2] = tf;
    ++s.pc;
    return true;
}

// 0x92 SWAP3 — swap the top with the 4-th item.
bool op_swap3(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 4) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 3];
    s.stack[s.stackPointer + 3] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 3];
    s.stackBE[s.stackPointer + 3] = tf;
    ++s.pc;
    return true;
}

// 0x93 SWAP4 — swap the top with the 5-th item.
bool op_swap4(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 5) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 4];
    s.stack[s.stackPointer + 4] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 4];
    s.stackBE[s.stackPointer + 4] = tf;
    ++s.pc;
    return true;
}

// 0x94 SWAP5 — swap the top with the 6-th item.
bool op_swap5(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 6) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 5];
    s.stack[s.stackPointer + 5] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 5];
    s.stackBE[s.stackPointer + 5] = tf;
    ++s.pc;
    return true;
}

// 0x95 SWAP6 — swap the top with the 7-th item.
bool op_swap6(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 7) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 6];
    s.stack[s.stackPointer + 6] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 6];
    s.stackBE[s.stackPointer + 6] = tf;
    ++s.pc;
    return true;
}

// 0x96 SWAP7 — swap the top with the 8-th item.
bool op_swap7(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 8) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 7];
    s.stack[s.stackPointer + 7] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 7];
    s.stackBE[s.stackPointer + 7] = tf;
    ++s.pc;
    return true;
}

// 0x97 SWAP8 — swap the top with the 9-th item.
bool op_swap8(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 9) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 8];
    s.stack[s.stackPointer + 8] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 8];
    s.stackBE[s.stackPointer + 8] = tf;
    ++s.pc;
    return true;
}

// 0x98 SWAP9 — swap the top with the 10-th item.
bool op_swap9(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 10) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 9];
    s.stack[s.stackPointer + 9] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 9];
    s.stackBE[s.stackPointer + 9] = tf;
    ++s.pc;
    return true;
}

// 0x99 SWAP10 — swap the top with the 11-th item.
bool op_swap10(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 11) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 10];
    s.stack[s.stackPointer + 10] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 10];
    s.stackBE[s.stackPointer + 10] = tf;
    ++s.pc;
    return true;
}

// 0x9a SWAP11 — swap the top with the 12-th item.
bool op_swap11(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 12) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 11];
    s.stack[s.stackPointer + 11] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 11];
    s.stackBE[s.stackPointer + 11] = tf;
    ++s.pc;
    return true;
}

// 0x9b SWAP12 — swap the top with the 13-th item.
bool op_swap12(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 13) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 12];
    s.stack[s.stackPointer + 12] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 12];
    s.stackBE[s.stackPointer + 12] = tf;
    ++s.pc;
    return true;
}

// 0x9c SWAP13 — swap the top with the 14-th item.
bool op_swap13(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 14) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 13];
    s.stack[s.stackPointer + 13] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 13];
    s.stackBE[s.stackPointer + 13] = tf;
    ++s.pc;
    return true;
}

// 0x9d SWAP14 — swap the top with the 15-th item.
bool op_swap14(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 15) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 14];
    s.stack[s.stackPointer + 14] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 14];
    s.stackBE[s.stackPointer + 14] = tf;
    ++s.pc;
    return true;
}

// 0x9e SWAP15 — swap the top with the 16-th item.
bool op_swap15(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 16) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 15];
    s.stack[s.stackPointer + 15] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 15];
    s.stackBE[s.stackPointer + 15] = tf;
    ++s.pc;
    return true;
}

// 0x9f SWAP16 — swap the top with the 17-th item.
bool op_swap16(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 17) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = s.stack[s.stackPointer];
    s.stack[s.stackPointer]      = s.stack[s.stackPointer + 16];
    s.stack[s.stackPointer + 16] = t;
    const uint8_t tf = s.stackBE[s.stackPointer];
    s.stackBE[s.stackPointer]      = s.stackBE[s.stackPointer + 16];
    s.stackBE[s.stackPointer + 16] = tf;
    ++s.pc;
    return true;
}

}  // namespace

void register_stack(InstrTable& t) {
    t[0x80] = &op_dup1;   t[0x81] = &op_dup2;   t[0x82] = &op_dup3;
    t[0x83] = &op_dup4;   t[0x84] = &op_dup5;   t[0x85] = &op_dup6;
    t[0x86] = &op_dup7;   t[0x87] = &op_dup8;   t[0x88] = &op_dup9;
    t[0x89] = &op_dup10;  t[0x8a] = &op_dup11;  t[0x8b] = &op_dup12;
    t[0x8c] = &op_dup13;  t[0x8d] = &op_dup14;  t[0x8e] = &op_dup15;
    t[0x8f] = &op_dup16;
    t[0x90] = &op_swap1;  t[0x91] = &op_swap2;  t[0x92] = &op_swap3;
    t[0x93] = &op_swap4;  t[0x94] = &op_swap5;  t[0x95] = &op_swap6;
    t[0x96] = &op_swap7;  t[0x97] = &op_swap8;  t[0x98] = &op_swap9;
    t[0x99] = &op_swap10; t[0x9a] = &op_swap11; t[0x9b] = &op_swap12;
    t[0x9c] = &op_swap13; t[0x9d] = &op_swap14; t[0x9e] = &op_swap15;
    t[0x9f] = &op_swap16;
}

}  // namespace zevm

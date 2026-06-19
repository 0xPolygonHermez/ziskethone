#pragma once
// stack.cpp — stack-shuffling opcodes: DUP1..DUP16 (0x80..0x8f) and
// SWAP1..SWAP16 (0x90..0x9f). POP lives in control.cpp.
//
// DUPn copies the n-th item from the top onto the top (depth + 1); SWAPn swaps
// the top with the (n+1)-th item (depth unchanged). Each costs GAS_VERYLOW. The
// stack grows downward: the top is stack[stackPointer], the i-th-from-top is
// stack[stackPointer + i], and depth == kStackLimit - stackPointer. The slots are
// 256-bit words moved verbatim — DUP/SWAP are endianness-agnostic.

#include "detail.hpp"

namespace zevm {

namespace stack_ops {

// 0x80 DUP1 — duplicate the 1st-from-top item.
bool op_dup1(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 1)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[1];
    ++R.pc;
    return true;
}

// 0x81 DUP2 — duplicate the 2nd-from-top item.
bool op_dup2(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[2];
    ++R.pc;
    return true;
}

// 0x82 DUP3 — duplicate the 3rd-from-top item.
bool op_dup3(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 3)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[3];
    ++R.pc;
    return true;
}

// 0x83 DUP4 — duplicate the 4th-from-top item.
bool op_dup4(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 4)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[4];
    ++R.pc;
    return true;
}

// 0x84 DUP5 — duplicate the 5th-from-top item.
bool op_dup5(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 5)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[5];
    ++R.pc;
    return true;
}

// 0x85 DUP6 — duplicate the 6th-from-top item.
bool op_dup6(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 6)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[6];
    ++R.pc;
    return true;
}

// 0x86 DUP7 — duplicate the 7th-from-top item.
bool op_dup7(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 7)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[7];
    ++R.pc;
    return true;
}

// 0x87 DUP8 — duplicate the 8th-from-top item.
bool op_dup8(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 8)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[8];
    ++R.pc;
    return true;
}

// 0x88 DUP9 — duplicate the 9th-from-top item.
bool op_dup9(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 9)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[9];
    ++R.pc;
    return true;
}

// 0x89 DUP10 — duplicate the 10th-from-top item.
bool op_dup10(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 10)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[10];
    ++R.pc;
    return true;
}

// 0x8a DUP11 — duplicate the 11th-from-top item.
bool op_dup11(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 11)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[11];
    ++R.pc;
    return true;
}

// 0x8b DUP12 — duplicate the 12th-from-top item.
bool op_dup12(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 12)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[12];
    ++R.pc;
    return true;
}

// 0x8c DUP13 — duplicate the 13th-from-top item.
bool op_dup13(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 13)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[13];
    ++R.pc;
    return true;
}

// 0x8d DUP14 — duplicate the 14th-from-top item.
bool op_dup14(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 14)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[14];
    ++R.pc;
    return true;
}

// 0x8e DUP15 — duplicate the 15th-from-top item.
bool op_dup15(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 15)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[15];
    ++R.pc;
    return true;
}

// 0x8f DUP16 — duplicate the 16th-from-top item.
bool op_dup16(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 16)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    R.top[0]   = R.top[16];
    ++R.pc;
    return true;
}

// 0x90 SWAP1 — swap the top with the 2-th item.
bool op_swap1(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[1];
    R.top[1] = t;
    ++R.pc;
    return true;
}

// 0x91 SWAP2 — swap the top with the 3-th item.
bool op_swap2(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 3)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[2];
    R.top[2] = t;
    ++R.pc;
    return true;
}

// 0x92 SWAP3 — swap the top with the 4-th item.
bool op_swap3(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 4)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[3];
    R.top[3] = t;
    ++R.pc;
    return true;
}

// 0x93 SWAP4 — swap the top with the 5-th item.
bool op_swap4(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 5)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[4];
    R.top[4] = t;
    ++R.pc;
    return true;
}

// 0x94 SWAP5 — swap the top with the 6-th item.
bool op_swap5(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 6)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[5];
    R.top[5] = t;
    ++R.pc;
    return true;
}

// 0x95 SWAP6 — swap the top with the 7-th item.
bool op_swap6(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 7)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[6];
    R.top[6] = t;
    ++R.pc;
    return true;
}

// 0x96 SWAP7 — swap the top with the 8-th item.
bool op_swap7(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 8)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[7];
    R.top[7] = t;
    ++R.pc;
    return true;
}

// 0x97 SWAP8 — swap the top with the 9-th item.
bool op_swap8(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 9)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[8];
    R.top[8] = t;
    ++R.pc;
    return true;
}

// 0x98 SWAP9 — swap the top with the 10-th item.
bool op_swap9(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 10)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[9];
    R.top[9] = t;
    ++R.pc;
    return true;
}

// 0x99 SWAP10 — swap the top with the 11-th item.
bool op_swap10(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 11)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[10];
    R.top[10] = t;
    ++R.pc;
    return true;
}

// 0x9a SWAP11 — swap the top with the 12-th item.
bool op_swap11(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 12)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[11];
    R.top[11] = t;
    ++R.pc;
    return true;
}

// 0x9b SWAP12 — swap the top with the 13-th item.
bool op_swap12(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 13)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[12];
    R.top[12] = t;
    ++R.pc;
    return true;
}

// 0x9c SWAP13 — swap the top with the 14-th item.
bool op_swap13(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 14)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[13];
    R.top[13] = t;
    ++R.pc;
    return true;
}

// 0x9d SWAP14 — swap the top with the 15-th item.
bool op_swap14(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 15)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[14];
    R.top[14] = t;
    ++R.pc;
    return true;
}

// 0x9e SWAP15 — swap the top with the 16-th item.
bool op_swap15(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 16)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[15];
    R.top[15] = t;
    ++R.pc;
    return true;
}

// 0x9f SWAP16 — swap the top with the 17-th item.
bool op_swap16(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 17)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0]      = R.top[16];
    R.top[16] = t;
    ++R.pc;
    return true;
}

}  // namespace


}  // namespace zevm

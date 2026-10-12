#pragma once
// stack.cpp — stack-shuffling opcodes: DUP1..DUP16 (0x80..0x8f),
// SWAP1..SWAP16 (0x90..0x9f) and, from Amsterdam, DUPN / SWAPN / EXCHANGE
// (0xe6..0xe8, EIP-8024). POP lives in control.cpp.
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
    R.top[-1] = R.top[0];
    return true;
}

// 0x81 DUP2 — duplicate the 2nd-from-top item.
bool op_dup2(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[1];
    return true;
}

// 0x82 DUP3 — duplicate the 3rd-from-top item.
bool op_dup3(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 3)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[2];
    return true;
}

// 0x83 DUP4 — duplicate the 4th-from-top item.
bool op_dup4(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 4)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[3];
    return true;
}

// 0x84 DUP5 — duplicate the 5th-from-top item.
bool op_dup5(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 5)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[4];
    return true;
}

// 0x85 DUP6 — duplicate the 6th-from-top item.
bool op_dup6(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 6)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[5];
    return true;
}

// 0x86 DUP7 — duplicate the 7th-from-top item.
bool op_dup7(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 7)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[6];
    return true;
}

// 0x87 DUP8 — duplicate the 8th-from-top item.
bool op_dup8(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 8)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[7];
    return true;
}

// 0x88 DUP9 — duplicate the 9th-from-top item.
bool op_dup9(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 9)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[8];
    return true;
}

// 0x89 DUP10 — duplicate the 10th-from-top item.
bool op_dup10(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 10)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[9];
    return true;
}

// 0x8a DUP11 — duplicate the 11th-from-top item.
bool op_dup11(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 11)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[10];
    return true;
}

// 0x8b DUP12 — duplicate the 12th-from-top item.
bool op_dup12(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 12)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[11];
    return true;
}

// 0x8c DUP13 — duplicate the 13th-from-top item.
bool op_dup13(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 13)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[12];
    return true;
}

// 0x8d DUP14 — duplicate the 14th-from-top item.
bool op_dup14(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 14)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[13];
    return true;
}

// 0x8e DUP15 — duplicate the 15th-from-top item.
bool op_dup15(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 15)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[14];
    return true;
}

// 0x8f DUP16 — duplicate the 16th-from-top item.
bool op_dup16(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 16)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[15];
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
    return true;
}

// ----- EIP-8024 (Amsterdam): DUPN / SWAPN / EXCHANGE -----
//
// Each takes a one-byte immediate (pc advances by 2; costs GAS_VERYLOW). The
// forbidden immediate ranges keep it from ever being JUMPDEST (0x5b) or a PUSH
// opcode, so JUMPDEST analysis is unchanged; a forbidden immediate is an
// undefined instruction. An immediate past the end of code reads as 0 (evmone
// pads code with zeros). Decoding follows evmone's decode_*_imm.

// The immediate byte after the opcode at pc.
inline uint8_t imm_byte(const EvmState& s, const Regs& R) {
    const size_t p = R.pc + 1;
    return p < s.codeSize ? s.code[p] : 0;
}

// DUPN / SWAPN: n in [17, 235], or 0 for a forbidden immediate (0x5b..0x7f).
inline unsigned decode_dupn_swapn(uint8_t imm) {
    if (imm >= 0x5b && imm <= 0x7f) return 0;
    return static_cast<uint8_t>(imm + 0x91);
}

// 0xe6 DUPN — duplicate the n-th item from the top.
bool op_dupn(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    const unsigned n = decode_dupn_swapn(imm_byte(s, R));
    if (n == 0) { s.status = EVMC_UNDEFINED_INSTRUCTION; return false; }
    if (depth_lt(R, n)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    R.top[-1] = R.top[n - 1];
    --R.top;
    R.pc += 2;
    return true;
}

// 0xe7 SWAPN — swap the top with the (n+1)-th item.
bool op_swapn(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    const unsigned n = decode_dupn_swapn(imm_byte(s, R));
    if (n == 0) { s.status = EVMC_UNDEFINED_INSTRUCTION; return false; }
    if (depth_lt(R, n + 1)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[0];
    R.top[0] = R.top[n];
    R.top[n] = t;
    R.pc += 2;
    return true;
}

// 0xe8 EXCHANGE — swap the (n+1)-th and (m+1)-th items, 1 <= n < m, n + m <= 30.
// The immediate is forbidden in 0x52..0x7f; otherwise k = imm ^ 0x8f splits into
// q = k / 16, r = k % 16 and (n, m) = q < r ? (q+1, r+1) : (r+1, 29-q).
bool op_exchange(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    const uint8_t imm = imm_byte(s, R);
    if (imm >= 0x52 && imm <= 0x7f) { s.status = EVMC_UNDEFINED_INSTRUCTION; return false; }
    const unsigned k = imm ^ 0x8fu;
    const unsigned q = k / 16, r = k % 16;
    const unsigned n = q < r ? q + 1 : r + 1;
    const unsigned m = q < r ? r + 1 : 29 - q;
    if (depth_lt(R, m + 1)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const U256 t = R.top[n];
    R.top[n] = R.top[m];
    R.top[m] = t;
    R.pc += 2;
    return true;
}

}  // namespace


}  // namespace zevm

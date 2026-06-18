#pragma once
// control.cpp — control-flow, halting & misc opcodes: STOP (0x00), JUMP (0x56),
// JUMPI (0x57), JUMPDEST (0x5b), POP (0x50), PC (0x58), GAS (0x5a).
//
// JUMP/JUMPI validate the target against the analyzer's push-data map via
// EvmState::is_jumpdest (a 0x5b opcode that isn't PUSH immediate data); an
// invalid target halts the frame with EVMC_BAD_JUMP_DESTINATION.

#include "detail.hpp"

namespace zevm {

namespace control_ops {

// 0x00 STOP — halt successfully.
bool op_stop(EvmState& s) {
    s.status = EVMC_SUCCESS;
    return false;  // stop
}

// The jump target as a code offset: any high limb set (or a value past code) is
// out of range, which is_jumpdest rejects. Takes a little-endian value (ld_le).
inline size_t jump_target(const U256& d) {
    return (d.limbs[1] | d.limbs[2] | d.limbs[3]) != 0 ? SIZE_MAX
                                                       : static_cast<size_t>(d.limbs[0]);
}

// 0x56 JUMP — set pc to a validated jump target.
bool op_jump(EvmState& s) {
    if (s.gas < GAS_MID) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_MID;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const size_t dest = jump_target(ld_le(s, s.stackPointer));
    ++s.stackPointer;  // pop the target
    if (!s.is_jumpdest(dest)) { s.status = EVMC_BAD_JUMP_DESTINATION; return false; }
    s.pc = dest;
    return true;
}

// 0x57 JUMPI — jump to the target if the condition is nonzero, else fall through.
bool op_jumpi(EvmState& s) {
    if (s.gas < GAS_HIGH) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_HIGH;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    // target (the condition is endianness-independent — zero is zero in BE too)
    const size_t dest = jump_target(ld_le(s, s.stackPointer));
    const bool   take = !u256_is_zero(s.stack[s.stackPointer + 1]);  // cond != 0
    s.stackPointer += 2;  // pop target and condition
    if (take) {
        if (!s.is_jumpdest(dest)) { s.status = EVMC_BAD_JUMP_DESTINATION; return false; }
        s.pc = dest;
    } else {
        ++s.pc;
    }
    return true;
}

// 0x5b JUMPDEST — valid jump-target marker; a no-op that just advances pc.
bool op_jumpdest(EvmState& s) {
    if (s.gas < GAS_JUMPDEST) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_JUMPDEST;
    ++s.pc;
    return true;
}

// 0x50 POP — discard the top stack item.
bool op_pop(EvmState& s) {
    if (s.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_BASE;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    ++s.stackPointer;
    ++s.pc;
    return true;
}

// 0x58 PC — push the program counter of this instruction.
bool op_pc(EvmState& s) {
    if (s.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_BASE;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    st_le(s, s.stackPointer, U256{{static_cast<uint64_t>(s.pc), 0, 0, 0}});
    ++s.pc;
    return true;
}

// 0x5a GAS — push the gas remaining after this instruction's own cost.
bool op_gas(EvmState& s) {
    if (s.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_BASE;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    st_le(s, s.stackPointer, U256{{static_cast<uint64_t>(s.gas), 0, 0, 0}});
    ++s.pc;
    return true;
}

}  // namespace


}  // namespace zevm

#pragma once
// control.cpp — control-flow, halting & misc opcodes: STOP (0x00), JUMP (0x56),
// JUMPI (0x57), JUMPDEST (0x5b), POP (0x50), PC (0x58), GAS (0x5a).
//
// JUMP/JUMPI validate the target against the analyzer's push-data map via
// EvmState::is_jumpdest (a 0x5b opcode that isn't PUSH immediate data); an
// invalid target halts the frame with EVMC_BAD_JUMP_DESTINATION.
//
// JUMPDEST fusion: a valid target is *always* a JUMPDEST (0x5b) — a no-op that
// only charges GAS_JUMPDEST and steps past itself. So a JUMP (and a taken JUMPI)
// fold that landing JUMPDEST in: charge its gas and resume at dest+1, saving a
// whole dispatch iteration. The charge order (jump gas → validate → jumpdest gas)
// is preserved, so gas/OOG/BAD_JUMP behaviour is identical. A JUMPDEST reached by
// fall-through still runs op_jumpdest normally.

#include "detail.hpp"

namespace zevm {

namespace control_ops {

// 0x00 STOP — halt successfully.
bool op_stop(EvmState& s, Regs& R) {
    s.status = EVMC_SUCCESS;
    return false;  // stop
}

// The jump target as a code offset: any high limb set (or a value past code) is
// out of range, which is_jumpdest rejects. Takes a little-endian value (ld_le).
inline size_t jump_target(const U256& d) {
    return (d.limbs[1] | d.limbs[2] | d.limbs[3]) != 0 ? SIZE_MAX
                                                       : static_cast<size_t>(d.limbs[0]);
}

// 0x56 JUMP — set pc to a validated jump target (landing JUMPDEST folded in).
bool op_jump(EvmState& s, Regs& R) {
    if (R.gas < GAS_MID) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_MID;
    if (depth_lt(R, 1)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const size_t dest = jump_target(ld_le(R.top));
    ++R.top;  // pop the target
    if (!s.is_jumpdest(dest)) { s.status = EVMC_BAD_JUMP_DESTINATION; return false; }
    // Fold the landing JUMPDEST: charge its gas and resume at dest+1.
    if (R.gas < GAS_JUMPDEST) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_JUMPDEST;
    R.pc = dest + 1;
    return true;
}

// 0x57 JUMPI — jump to the target if the condition is nonzero, else fall through.
bool op_jumpi(EvmState& s, Regs& R) {
    if (R.gas < GAS_HIGH) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_HIGH;
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    // target (the condition is endianness-independent — zero is zero in BE too)
    const size_t dest = jump_target(ld_le(R.top));
    const bool   take = !u256_is_zero(R.top[1]);  // cond != 0
    R.top += 2;  // pop target and condition
    if (take) {
        if (!s.is_jumpdest(dest)) { s.status = EVMC_BAD_JUMP_DESTINATION; return false; }
        // Fold the landing JUMPDEST: charge its gas and resume at dest+1.
        if (R.gas < GAS_JUMPDEST) { s.status = EVMC_OUT_OF_GAS; return false; }
        R.gas -= GAS_JUMPDEST;
        R.pc = dest + 1;
    } else {
        ++R.pc;
    }
    return true;
}

// 0x5b JUMPDEST — valid jump-target marker; a no-op that just advances pc.
bool op_jumpdest(EvmState& s, Regs& R) {
    if (R.gas < GAS_JUMPDEST) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_JUMPDEST;
    ++R.pc;
    return true;
}

// 0x50 POP — discard the top stack item.
bool op_pop(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    if (depth_lt(R, 1)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    ++R.top;
    ++R.pc;
    return true;
}

// 0x58 PC — push the program counter of this instruction.
bool op_pc(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    st_le(R.top, U256{{static_cast<uint64_t>(R.pc), 0, 0, 0}});
    ++R.pc;
    return true;
}

// 0x5a GAS — push the gas remaining after this instruction's own cost.
bool op_gas(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.top;
    st_le(R.top, U256{{static_cast<uint64_t>(R.gas), 0, 0, 0}});
    ++R.pc;
    return true;
}

}  // namespace


}  // namespace zevm

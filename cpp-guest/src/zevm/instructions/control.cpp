// control.cpp — control-flow & halting opcodes: STOP (0x00), JUMP (0x56),
// JUMPI (0x57), JUMPDEST (0x5b). (POP/PC/GAS as they land.)
//
// JUMP/JUMPI validate the target against the analyzer's push-data map via
// EvmState::is_jumpdest (a 0x5b opcode that isn't PUSH immediate data); an
// invalid target halts the frame with EVMC_BAD_JUMP_DESTINATION.

#include "detail.hpp"

namespace zevm {

namespace {

// 0x00 STOP — halt successfully.
bool op_stop(EvmState& s) {
    s.status = EVMC_SUCCESS;
    return false;  // stop
}

// The jump target as a code offset: any high limb set (or a value past code) is
// out of range, which is_jumpdest rejects. Caller must to_le the slot first.
inline size_t jump_target(const U256& d) {
    return (d.limbs[1] | d.limbs[2] | d.limbs[3]) != 0 ? SIZE_MAX
                                                       : static_cast<size_t>(d.limbs[0]);
}

// 0x56 JUMP — set pc to a validated jump target.
bool op_jump(EvmState& s) {
    if (s.gas < GAS_MID) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_MID;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    const size_t dest = jump_target(s.stack[s.stackPointer]);
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
    to_le(s, s.stackPointer);  // target (the condition is endianness-independent)
    const size_t dest = jump_target(s.stack[s.stackPointer]);
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

}  // namespace

void register_control(InstrTable& t) {
    t[0x00] = &op_stop;
    t[0x56] = &op_jump;
    t[0x57] = &op_jumpi;
    t[0x5b] = &op_jumpdest;
}

}  // namespace zevm

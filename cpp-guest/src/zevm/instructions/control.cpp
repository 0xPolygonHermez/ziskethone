// control.cpp — control-flow & halting opcodes (STOP, JUMPDEST today; POP, JUMP,
// JUMPI, PC, GAS as they land — 0x00, 0x50, 0x56..0x5b).

#include "detail.hpp"

namespace zevm {

namespace {

// 0x00 STOP — halt successfully.
bool op_stop(EvmState& s) {
    s.status = EVMC_SUCCESS;
    return false;  // stop
}

// 0x5b JUMPDEST — valid jump target marker; a no-op that just advances pc.
bool op_jumpdest(EvmState& s) {
    ++s.pc;
    return true;
}

}  // namespace

void register_control(InstrTable& t) {
    t[0x00] = &op_stop;
    t[0x5b] = &op_jumpdest;
}

}  // namespace zevm

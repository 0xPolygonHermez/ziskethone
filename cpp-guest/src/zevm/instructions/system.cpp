// system.cpp — system / call family (CREATE, CALL, CALLCODE, RETURN, DELEGATECALL,
// CREATE2, STATICCALL, REVERT, INVALID, SELFDESTRUCT — 0xf0..0xff).

#include "detail.hpp"

namespace zevm {

namespace {

// 0xfe INVALID — designated invalid opcode; consumes all gas (real semantics
// will zero gas), halts with failure.
bool op_invalid(EvmState& s) {
    s.status = EVMC_INVALID_INSTRUCTION;
    return false;  // stop
}

}  // namespace

void register_system(InstrTable& t) {
    t[0xfe] = &op_invalid;
}

}  // namespace zevm

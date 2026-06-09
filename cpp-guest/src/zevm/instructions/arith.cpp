// arith.cpp — arithmetic opcodes (0x01..0x0b: ADD, MUL, SUB, DIV, MOD, EXP, ...).
//
// Prime candidates for the ZisK-accelerated zeg::bi backend, since the stack
// words are already in its little-endian uint64_t[4] layout.

#include "detail.hpp"

#include "bigint/backend.hpp"  // zeg::bi::add256 — ZisK-accelerated 256-bit add

namespace zevm {

namespace {

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

}  // namespace

void register_arith(InstrTable& t) {
    t[0x01] = &op_add;
}

}  // namespace zevm

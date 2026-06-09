// memory.cpp — memory opcodes (MLOAD 0x51, MSTORE 0x52, MSTORE8 0x53,
// MSIZE 0x59 today; MCOPY 0x5e to follow). Backed by the static EVMMem manager.
//
// Both opcodes take a 256-bit byte offset off the stack. EVMMem::readBytes /
// writeBytes grow the frame's memory and charge the quadratic expansion gas (on
// top of the opcode's GAS_VERYLOW base), returning OutOfGas without mutating
// state if it can't be paid. An offset that doesn't fit in a byte index — any
// high limb set — addresses far beyond what gas could ever cover, so it's an
// immediate out-of-gas.

#include "detail.hpp"

#include "evm_mem.hpp"

namespace zevm {

namespace {

// 0x51 MLOAD — push the 32 bytes at memory[offset..offset+32) (big-endian).
bool op_mload(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    U256& off = s.stack[s.stackPointer];  // offset (top), overwritten with the result
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;        // offset >= 2^64: unaffordable expansion
        return false;
    }
    uint8_t buf[32];
    if (EVMMem::readBytes(static_cast<size_t>(off.limbs[0]), buf, 32, &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    off = u256_from_be(buf);               // pop offset, push the loaded word (same slot)
    ++s.pc;
    return true;
}

// 0x52 MSTORE — write value (32 bytes, big-endian) to memory[offset..offset+32).
bool op_mstore(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const U256& off = s.stack[s.stackPointer];      // offset (top)
    const U256& val = s.stack[s.stackPointer + 1];  // value (second)
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    uint8_t buf[32];
    u256_to_be(val, buf);
    if (EVMMem::writeBytes(static_cast<size_t>(off.limbs[0]), buf, 32, &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    s.stackPointer += 2;  // pop offset and value
    ++s.pc;
    return true;
}

// 0x53 MSTORE8 — write the low byte of value to memory[offset].
bool op_mstore8(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const U256& off = s.stack[s.stackPointer];      // offset (top)
    const U256& val = s.stack[s.stackPointer + 1];  // value (second)
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const uint8_t byte = static_cast<uint8_t>(val.limbs[0]);  // value mod 256
    if (EVMMem::writeByte(static_cast<size_t>(off.limbs[0]), byte, &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    s.stackPointer += 2;  // pop offset and value
    ++s.pc;
    return true;
}

// 0x59 MSIZE — push the current memory size in bytes (always word-aligned).
bool op_msize(EvmState& s) {
    if (s.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_BASE;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }

    --s.stackPointer;
    s.stack[s.stackPointer] = U256{{static_cast<uint64_t>(EVMMem::size()), 0, 0, 0}};
    ++s.pc;
    return true;
}

}  // namespace

void register_memory(InstrTable& t) {
    t[0x51] = &op_mload;
    t[0x52] = &op_mstore;
    t[0x53] = &op_mstore8;
    t[0x59] = &op_msize;
}

}  // namespace zevm

// memory.cpp — memory opcodes (MLOAD 0x51, MSTORE 0x52, MSTORE8 0x53,
// MSIZE 0x59 today; MCOPY 0x5e to follow). Backed by the static EVMMem manager.
//
// Memory is big-endian, which is exactly the BE stack representation (the 32
// wire bytes laid out as four little-endian limbs == the value's raw bytes). So
// with lazy endianness MLOAD reads straight into the slot and tags it BE, and
// MSTORE writes a BE value's bytes out with no conversion. The byte offset, by
// contrast, is an integer, so it is forced to LE before use. An offset with any
// high limb set addresses far beyond what gas could cover -> out-of-gas.

#include "detail.hpp"

#include "evm_mem.hpp"

namespace zevm {

namespace {

// 0x51 MLOAD — push the 32 bytes at memory[offset..offset+32) (big-endian, so
// the result is left in BE form).
bool op_mload(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    to_le(s, s.stackPointer);             // offset as an integer
    U256& slot = s.stack[s.stackPointer]; // offset, overwritten with the loaded word
    if ((slot.limbs[1] | slot.limbs[2] | slot.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const size_t addr = static_cast<size_t>(slot.limbs[0]);
    if (EVMMem::readBytes(addr, reinterpret_cast<uint8_t*>(&slot), 32, &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    s.stackBE[s.stackPointer] = kBE;       // raw memory bytes are the BE form
    ++s.pc;
    return true;
}

// 0x52 MSTORE — write value (big-endian) to memory[offset..offset+32).
bool op_mstore(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    to_le(s, s.stackPointer);  // offset
    const U256& off = s.stack[s.stackPointer];
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const size_t addr = static_cast<size_t>(off.limbs[0]);

    to_be(s, s.stackPointer + 1);  // value -> big-endian bytes (no-op if already BE)
    const U256& val = s.stack[s.stackPointer + 1];
    if (EVMMem::writeBytes(addr, reinterpret_cast<const uint8_t*>(&val), 32, &s.gas) != MemError::Ok) {
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

    to_le(s, s.stackPointer);  // offset
    const U256& off = s.stack[s.stackPointer];
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const size_t addr = static_cast<size_t>(off.limbs[0]);

    // value mod 256 — the least-significant byte, wherever endianness puts it.
    const U256& val = s.stack[s.stackPointer + 1];
    const uint8_t byte = s.stackBE[s.stackPointer + 1]
                             ? static_cast<uint8_t>(val.limbs[3] >> 56)
                             : static_cast<uint8_t>(val.limbs[0]);
    if (EVMMem::writeByte(addr, byte, &s.gas) != MemError::Ok) {
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
    s.stackBE[s.stackPointer] = kLE;  // a freshly computed integer
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

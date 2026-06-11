// memory.cpp — memory opcodes (MLOAD 0x51, MSTORE 0x52, MSTORE8 0x53,
// MSIZE 0x59, MCOPY 0x5e). Backed by the static EVMMem manager.
//
// Memory is big-endian, which is exactly the BE stack representation (the 32
// wire bytes laid out as four little-endian limbs == the slot's raw bytes). So
// MLOAD reads straight into the slot and MSTORE writes a slot's bytes out with
// no conversion. Byte offsets, by contrast, are integers, so they are loaded as
// little-endian (ld_le) before use; an offset with any high limb set addresses
// far beyond what gas could cover -> out-of-gas.

#include "detail.hpp"

#include <algorithm>
#include <cstring>

#include "evm_mem.hpp"

namespace zevm {

namespace {

// 0x51 MLOAD — push the 32 bytes at memory[offset..offset+32) (big-endian, which
// is the BE slot form directly).
bool op_mload(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const U256 off = ld_le(s, s.stackPointer);  // offset as an integer
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const size_t addr = static_cast<size_t>(off.limbs[0]);
    U256& slot = s.stack[s.stackPointer];  // overwritten with the loaded word
    if (EVMMem::readBytes(addr, reinterpret_cast<uint8_t*>(&slot), 32, &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    // raw memory bytes are the BE form — slot is already correct, no swap
    ++s.pc;
    return true;
}

// 0x52 MSTORE — write value (big-endian) to memory[offset..offset+32).
bool op_mstore(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const U256 off = ld_le(s, s.stackPointer);  // offset
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const size_t addr = static_cast<size_t>(off.limbs[0]);

    const U256& val = s.stack[s.stackPointer + 1];  // already big-endian bytes
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

    const U256 off = ld_le(s, s.stackPointer);  // offset
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const size_t addr = static_cast<size_t>(off.limbs[0]);

    // value mod 256 — the least-significant byte, which in BE form is the last
    // byte (high half of the top limb).
    const U256& val = s.stack[s.stackPointer + 1];
    const uint8_t byte = static_cast<uint8_t>(val.limbs[3] >> 56);
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
    st_le(s, s.stackPointer, U256{{static_cast<uint64_t>(EVMMem::size()), 0, 0, 0}});
    ++s.pc;
    return true;
}

// 0x5e MCOPY (Cancun, EIP-5656) — copy `size` bytes within memory, src -> dst.
bool op_mcopy(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 3) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const uint32_t sp = s.stackPointer;
    const uint64_t dst  = mem_arg(ld_le(s, sp));
    const uint64_t src  = mem_arg(ld_le(s, sp + 1));
    const uint64_t size = mem_arg(ld_le(s, sp + 2));

    // Grow once to cover both windows (the higher of dst/src + size).
    const uint64_t hi = dst > src ? dst : src;
    if (EVMMem::expand(static_cast<size_t>(hi), static_cast<size_t>(size), &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    const int64_t cc = copy_cost(size);
    if (s.gas < cc) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= cc;

    if (size != 0)  // overlap-safe
        std::memmove(EVMMem::data(static_cast<size_t>(dst)),
                     EVMMem::data(static_cast<size_t>(src)), static_cast<size_t>(size));
    s.stackPointer += 3;
    ++s.pc;
    return true;
}

}  // namespace

void register_memory(InstrTable& t, evmc_revision rev) {
    t[0x51] = &op_mload;
    t[0x52] = &op_mstore;
    t[0x53] = &op_mstore8;
    t[0x59] = &op_msize;
    if (rev >= EVMC_CANCUN)  // EIP-5656
        t[0x5e] = &op_mcopy;
}

}  // namespace zevm

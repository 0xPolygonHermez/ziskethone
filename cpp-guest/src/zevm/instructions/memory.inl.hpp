#pragma once
// memory.cpp — memory opcodes (MLOAD 0x51, MSTORE 0x52, MSTORE8 0x53,
// MSIZE 0x59, MCOPY 0x5e). Backed by the static EVMMem manager.
//
// Memory is big-endian; the stack stores little-endian integers, so MLOAD
// byteswaps the 32 wire bytes into the slot (u256_from_be) and MSTORE byteswaps
// the slot back out (u256_to_be). Byte offsets are integers held in the low lane:
// an offset with any high limb set addresses far beyond what gas could cover ->
// out-of-gas.

#include "detail.hpp"

#include <algorithm>
#include <cstring>

#include "evm_mem.hpp"

namespace zevm {

namespace memory_ops {

// 0x51 MLOAD — push the 32 bytes at memory[offset..offset+32); the wire bytes are
// big-endian, byteswapped into the little-endian slot.
bool op_mload(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const U256& off = s.stack[R.sp];  // offset (little-endian slot)
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const size_t addr = static_cast<size_t>(off.limbs[0]);
    uint8_t be[32];
    if (mem_read(s, R, addr, be, 32) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    s.stack[R.sp] = u256_from_be(be);  // BE wire bytes -> LE slot
    ++R.pc;
    return true;
}

// 0x52 MSTORE — write value to memory[offset..offset+32) as 32 big-endian bytes.
bool op_mstore(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const U256& off = s.stack[R.sp];  // offset (little-endian slot)
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const size_t addr = static_cast<size_t>(off.limbs[0]);

    uint8_t be[32];
    u256_to_be(s.stack[R.sp + 1], be);  // LE slot -> BE wire bytes
    if (mem_write(s, R, addr, be, 32) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    R.sp += 2;  // pop offset and value
    ++R.pc;
    return true;
}

// 0x53 MSTORE8 — write the low byte of value to memory[offset].
bool op_mstore8(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const U256& off = s.stack[R.sp];  // offset (little-endian slot)
    if ((off.limbs[1] | off.limbs[2] | off.limbs[3]) != 0) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const size_t addr = static_cast<size_t>(off.limbs[0]);

    // value mod 256 — the least-significant byte, which in LE form is the low
    // byte of the low lane.
    const U256& val = s.stack[R.sp + 1];
    const uint8_t byte = static_cast<uint8_t>(val.limbs[0] & 0xFF);
    if (mem_write_byte(s, R, addr, byte) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    R.sp += 2;  // pop offset and value
    ++R.pc;
    return true;
}

// 0x59 MSIZE — push the current memory size in bytes (always word-aligned).
bool op_msize(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    if (stack_depth(R.sp) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }

    --R.sp;
    st_le(s, R.sp, U256{{static_cast<uint64_t>(EVMMem::size()), 0, 0, 0}});
    ++R.pc;
    return true;
}

// 0x5e MCOPY (Cancun, EIP-5656) — copy `size` bytes within memory, src -> dst.
bool op_mcopy(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 3) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const uint32_t sp = R.sp;
    const uint64_t dst  = mem_arg(s.stack[sp]);
    const uint64_t src  = mem_arg(s.stack[sp + 1]);
    const uint64_t size = mem_arg(s.stack[sp + 2]);

    // Grow once to cover both windows (the higher of dst/src + size).
    const uint64_t hi = dst > src ? dst : src;
    if (mem_expand(s, R, static_cast<size_t>(hi), static_cast<size_t>(size)) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    const int64_t cc = copy_cost(size);
    if (R.gas < cc) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= cc;

    if (size != 0)  // overlap-safe
        std::memmove(EVMMem::data(static_cast<size_t>(dst)),
                     EVMMem::data(static_cast<size_t>(src)), static_cast<size_t>(size));
    R.sp += 3;
    ++R.pc;
    return true;
}

}  // namespace


}  // namespace zevm

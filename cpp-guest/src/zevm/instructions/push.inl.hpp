#pragma once
// push.cpp — PUSH0 (0x5f) and PUSH1..PUSH32 (0x60..0x7f).
//
// A PUSH's n immediate bytes are big-endian and right-aligned in the 256-bit
// word. The stack stores little-endian integers (see EvmState::stack), so we
// byteswap them in: build the big-endian buffer [ (32-n) zero bytes ][ the n code
// bytes ] and run it through u256_from_be. A PUSH whose data runs past the end of
// code zero-pads the missing low-order bytes (avail). PUSH0 is the constant zero.
//
// PUSH1..PUSH8 take a fast path: their value fits the low 64-bit lane (limbs[0]).
// Instead of a variable-length memcpy we do one 8-byte load and a compile-time
// shift — the load reads the N immediate bytes (and a few following opcodes),
// bswap64 puts them in big-endian integer order, and the right shift by (8-N)*8
// discards the trailing over-read bytes. It needs 8 readable bytes; a PUSH whose
// immediate is truncated at code end (only the last few bytes) falls back to the
// zero-padding path.

#include "detail.hpp"

namespace zevm {

namespace push_ops {

// Shared PUSH1..PUSH8 fast path (N = 1..8). See the file header.
template <unsigned N>
inline bool push_small(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    U256& w = s.stack[s.stackPointer];
    w.limbs[1] = 0; w.limbs[2] = 0; w.limbs[3] = 0;
    const size_t pc1 = s.pc + 1;
    if (pc1 + 8 <= s.codeSize) {
        // 8 bytes safely readable: load them, byteswap to big-endian integer
        // order, then drop the (8-N) trailing over-read bytes.
        w.limbs[0] = bswap64(load_u64(s.code + pc1)) >> ((8 - N) * 8);
    } else {
        // Near code end: the immediate may be truncated -> zero-pad the missing
        // low-order bytes. Rare. The avail bytes are the high-order ones.
        uint8_t be[8] = {};
        const size_t avail = pc1 < s.codeSize ? std::min<size_t>(N, s.codeSize - pc1) : 0;
        std::memcpy(be, s.code + pc1, avail);  // big-endian, left-aligned
        uint64_t v = 0;
        for (unsigned i = 0; i < N; ++i) v = (v << 8) | be[i];
        w.limbs[0] = v;
    }
    s.pc += N + 1;
    return true;
}

// Shared PUSH9..PUSH32 path (N = 9..32). Build the right-aligned big-endian buffer
// and byteswap it into the little-endian slot. See the file header.
template <unsigned N>
inline bool push_big(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    const size_t pc1 = s.pc + 1;
    uint8_t be[32] = {};
    const size_t avail = pc1 < s.codeSize ? std::min<size_t>(N, s.codeSize - pc1) : 0;
    std::memcpy(be + (32 - N), s.code + pc1, avail);  // right-aligned; low bytes 0 if truncated
    s.stack[s.stackPointer] = u256_from_be(be);
    s.pc += N + 1;
    return true;
}

// 0x5f PUSH0 (Shanghai, EIP-3855) — push the constant zero.
bool op_push0(EvmState& s) {
    if (s.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_BASE;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer] = U256{};
    ++s.pc;
    return true;
}

// 0x60..0x67 PUSH1..PUSH8 — value fits the low lane (see push_small).
bool op_push1(EvmState& s) { return push_small<1>(s); }
bool op_push2(EvmState& s) { return push_small<2>(s); }
bool op_push3(EvmState& s) { return push_small<3>(s); }
bool op_push4(EvmState& s) { return push_small<4>(s); }
bool op_push5(EvmState& s) { return push_small<5>(s); }
bool op_push6(EvmState& s) { return push_small<6>(s); }
bool op_push7(EvmState& s) { return push_small<7>(s); }
bool op_push8(EvmState& s) { return push_small<8>(s); }

// 0x68..0x7f PUSH9..PUSH32 — value spans more than the low lane (see push_big).
bool op_push9(EvmState& s)  { return push_big<9>(s); }
bool op_push10(EvmState& s) { return push_big<10>(s); }
bool op_push11(EvmState& s) { return push_big<11>(s); }
bool op_push12(EvmState& s) { return push_big<12>(s); }
bool op_push13(EvmState& s) { return push_big<13>(s); }
bool op_push14(EvmState& s) { return push_big<14>(s); }
bool op_push15(EvmState& s) { return push_big<15>(s); }
bool op_push16(EvmState& s) { return push_big<16>(s); }
bool op_push17(EvmState& s) { return push_big<17>(s); }
bool op_push18(EvmState& s) { return push_big<18>(s); }
bool op_push19(EvmState& s) { return push_big<19>(s); }
bool op_push20(EvmState& s) { return push_big<20>(s); }
bool op_push21(EvmState& s) { return push_big<21>(s); }
bool op_push22(EvmState& s) { return push_big<22>(s); }
bool op_push23(EvmState& s) { return push_big<23>(s); }
bool op_push24(EvmState& s) { return push_big<24>(s); }
bool op_push25(EvmState& s) { return push_big<25>(s); }
bool op_push26(EvmState& s) { return push_big<26>(s); }
bool op_push27(EvmState& s) { return push_big<27>(s); }
bool op_push28(EvmState& s) { return push_big<28>(s); }
bool op_push29(EvmState& s) { return push_big<29>(s); }
bool op_push30(EvmState& s) { return push_big<30>(s); }
bool op_push31(EvmState& s) { return push_big<31>(s); }
bool op_push32(EvmState& s) { return push_big<32>(s); }

}  // namespace


}  // namespace zevm

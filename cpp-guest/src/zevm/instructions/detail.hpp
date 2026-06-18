// detail.hpp — internal shared bits for the zevm opcode handlers.
//
// Included by every instructions/<category>.cpp. Holds the small helpers the
// handlers share (gas tiers, stack depth, unaligned loads, the inline byte
// swap) plus the per-category table-registration declarations consumed by
// table.cpp. Not a public header — the dispatch surface is instructions.hpp.

#pragma once

#include <algorithm>  // std::min (PUSH zero-pad fallback)
#include <cstddef>
#include <cstdint>
#include <cstring>    // std::memcpy (unaligned PUSH loads)

#include "evm_state.hpp"     // EvmState, kStackLimit
#include "instructions.hpp"  // InstrFn, InstrTable
#include "u256.hpp"          // U256, byteswap256, u256_* value helpers

namespace zevm {

// EVM gas cost tiers (subset; grows as opcodes land).
inline constexpr int64_t GAS_JUMPDEST = 1;  // JUMPDEST
inline constexpr int64_t GAS_BASE    = 2;   // MSIZE, PC, POP, GAS, address/block info, ...
inline constexpr int64_t GAS_VERYLOW = 3;   // ADD, SUB, NOT, PUSH, LT, AND, SHL, MLOAD, ...
inline constexpr int64_t GAS_LOW     = 5;   // MUL, DIV, SDIV, MOD, SMOD, SIGNEXTEND
inline constexpr int64_t GAS_MID     = 8;   // ADDMOD, MULMOD, JUMP
inline constexpr int64_t GAS_HIGH    = 10;  // JUMPI
inline constexpr int64_t GAS_EXP     = 10;  // EXP base
inline constexpr int64_t GAS_EXPBYTE = 50;  // EXP per byte of exponent (>= Spurious Dragon)

// Number of live operands on the stack. stackPointer counts DOWN from
// kStackLimit (empty) toward 0 (full), so depth == kStackLimit - stackPointer.
inline size_t stack_depth(const EvmState& s) {
    return kStackLimit - s.stackPointer;
}

// Unaligned 64-bit load from code.
inline uint64_t load_u64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

// Stack representation: every slot holds its value as a little-endian integer
// (limbs[0] = least significant, exactly the limb layout zeg::bi and the u256_*
// integer helpers consume). That makes the arithmetic and positional ops
// conversion-free — ld_le/st_le below are now identity. The cost moves to the
// *wire boundary*: memory / storage / PUSH / addresses / hashes are big-endian on
// the wire, so they byteswap into/out of the slot via u256_from_be / u256_to_be.
// The bit-parallel ops (AND/OR/XOR/NOT) and zero/equality tests (ISZERO/EQ) are
// representation-agnostic and work on the slots directly.

// Stack slot `i` as a little-endian value. The slot already holds LE limbs, so
// this is just a copy (kept as a named accessor so the arithmetic handlers read
// clearly and to localize the representation choice).
inline U256 ld_le(const EvmState& s, uint32_t i) { return s.stack[i]; }

// Store a little-endian value into slot `i` (the slot is LE — a plain copy).
inline void st_le(EvmState& s, uint32_t i, const U256& v) { s.stack[i] = v; }

// A 256-bit little-endian stack slot used as a memory offset/size: its integer
// value when it fits in 64 bits (the low lane), or UINT64_MAX when any higher
// lane is set (which forces an out-of-gas in EVMMem::expand, matching the EVM
// "offset too large" behaviour).
inline uint64_t mem_arg(const U256& v) {
    return (v.limbs[1] | v.limbs[2] | v.limbs[3]) != 0 ? UINT64_MAX : v.limbs[0];
}

// The 20-byte address held in stack slot value `v` (its low 160 bits): the
// value's big-endian bytes with the high 12 dropped.
inline evmc_address addr_from_slot(const U256& v) {
    uint8_t be[32];
    u256_to_be(v, be);
    evmc_address a;
    std::memcpy(a.bytes, be + 12, 20);
    return a;
}

// A stack slot value holding a 20-byte address right-aligned in the low 160 bits.
inline U256 slot_from_address(const evmc_address& a) {
    uint8_t be[32] = {};
    std::memcpy(be + 12, a.bytes, 20);
    return u256_from_be(be);
}

// Number of 32-byte EVM words spanned by `n` bytes.
inline int64_t num_words(uint64_t n) {
    return static_cast<int64_t>((n + 31) / 32);
}

// Gas to copy `n` bytes: G_copy = 3 per word (CALLDATACOPY/CODECOPY/EXTCODECOPY/
// MCOPY, on top of their VERYLOW base).
inline int64_t copy_cost(uint64_t n) {
    return num_words(n) * 3;
}

// Per-category table registration. Each is defined in its own translation unit
// (instructions/<category>.cpp) and slots its handlers into `t`; table.cpp calls
// them all over the default-filled table.
// The `rev` overloads gate fork-introduced opcodes: an opcode is registered only
// when `rev` is at or past the fork that introduced it (otherwise it stays
// op_unimplemented, i.e. undefined).
void register_arith(InstrTable& t);
void register_bitwise(InstrTable& t, evmc_revision rev);
void register_keccak(InstrTable& t);
void register_env(InstrTable& t, evmc_revision rev);
void register_memory(InstrTable& t, evmc_revision rev);
void register_storage(InstrTable& t, evmc_revision rev);
void register_control(InstrTable& t);
void register_stack(InstrTable& t);
void register_push(InstrTable& t, evmc_revision rev);
void register_log(InstrTable& t);
void register_system(InstrTable& t, evmc_revision rev);

}  // namespace zevm

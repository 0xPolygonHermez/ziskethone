// detail.hpp — internal shared bits for the zevm opcode handlers.
//
// Included by every instructions/<category>.cpp. Holds the small helpers the
// handlers share (gas tiers, stack depth, unaligned loads, the libgcc byte
// swap) plus the per-category table-registration declarations consumed by
// table.cpp. Not a public header — the dispatch surface is instructions.hpp.

#pragma once

#include <algorithm>  // std::min (PUSH zero-pad fallback)
#include <cstddef>
#include <cstdint>
#include <cstring>    // std::memcpy (unaligned PUSH loads)

#include "evm_state.hpp"     // EvmState, kStackLimit
#include "instructions.hpp"  // InstrFn, InstrTable
#include "u256.hpp"          // U256, u256_from_be/to_be, __bswapdi2

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

// Stack-entry endianness flags (EvmState::stackBE values).
enum : uint8_t { kLE = 0, kBE = 1 };

// Convert stack entry `i` to little-endian (the form zeg::bi and the integer
// helpers expect); no-op if already LE.
inline void to_le(EvmState& s, uint32_t i) {
    if (s.stackBE[i]) { s.stack[i] = byteswap256(s.stack[i]); s.stackBE[i] = kLE; }
}

// Convert stack entry `i` to big-endian (the form memory wants); no-op if already
// BE.
inline void to_be(EvmState& s, uint32_t i) {
    if (!s.stackBE[i]) { s.stack[i] = byteswap256(s.stack[i]); s.stackBE[i] = kBE; }
}

// A 256-bit stack value used as a memory offset/size: its integer value, or
// UINT64_MAX when any high limb is set (which forces an out-of-gas in
// EVMMem::expand, matching the EVM "offset too large" behaviour).
inline uint64_t mem_arg(const U256& v) {
    return (v.limbs[1] | v.limbs[2] | v.limbs[3]) != 0 ? UINT64_MAX : v.limbs[0];
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

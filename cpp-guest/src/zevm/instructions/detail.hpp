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

// Stack representation: every slot holds its value in big-endian wire form (the
// 32 bytes memory / storage / PUSH / the host's evmc_bytes32 use, stored as four
// little-endian words == byteswap256 of the integer value). That makes the
// common ops — DUP/SWAP/POP, MLOAD/MSTORE, SLOAD/SSTORE, addresses, hashes —
// conversion-free, since they're already BE. Only the arithmetic and positional
// ops need little-endian limbs (what zeg::bi and the integer helpers consume):
// they load a local LE copy with ld_le, compute, and write the result back as BE
// with st_le. The bit-parallel ops (AND/OR/XOR/NOT) and zero/equality tests
// (ISZERO/EQ) are representation-agnostic and work on the BE slots directly.

// Big-endian stack slot `i` -> its little-endian value (a copy; slot unchanged).
inline U256 ld_le(const EvmState& s, uint32_t i) { return byteswap256(s.stack[i]); }

// Store a little-endian value into slot `i` in big-endian form.
inline void st_le(EvmState& s, uint32_t i, const U256& v) { s.stack[i] = byteswap256(v); }

// A 256-bit big-endian stack slot used as a memory offset/size: its integer
// value when it fits in 64 bits, or UINT64_MAX when any higher byte is set
// (which forces an out-of-gas in EVMMem::expand, matching the EVM "offset too
// large" behaviour). Reads the slot directly — only the low lane (limbs[3], the
// big-endian least-significant 8 bytes) is byteswapped, and the three high lanes
// just have to be zero — rather than a full byteswap256 via ld_le.
inline uint64_t mem_arg(const U256& be) {
    return (be.limbs[0] | be.limbs[1] | be.limbs[2]) != 0 ? UINT64_MAX
                                                          : bswap64(be.limbs[3]);
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

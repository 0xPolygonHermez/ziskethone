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
#include "u256.hpp"          // U256, u256_from_be

// libgcc 64-bit byte swap. On the ZisK target (rv64ima, no Zbb) there is no
// hardware byteswap instruction, so this resolves to the soft implementation in
// zisk/compiler_rt.cpp; on the host it comes from the compiler-rt builtins.
extern "C" uint64_t __bswapdi2(uint64_t);

namespace zevm {

// EVM gas cost tiers (subset; grows as opcodes land).
inline constexpr int64_t GAS_VERYLOW = 3;   // ADD, SUB, NOT, PUSH, LT, AND, SHL, ...
inline constexpr int64_t GAS_LOW     = 5;   // MUL, DIV, SDIV, MOD, SMOD, SIGNEXTEND
inline constexpr int64_t GAS_MID     = 8;   // ADDMOD, MULMOD
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

// Per-category table registration. Each is defined in its own translation unit
// (instructions/<category>.cpp) and slots its handlers into `t`; table.cpp calls
// them all over the default-filled table.
void register_arith(InstrTable& t);
void register_bitwise(InstrTable& t);
void register_keccak(InstrTable& t);
void register_env(InstrTable& t);
void register_memory(InstrTable& t);
void register_storage(InstrTable& t);
void register_control(InstrTable& t);
void register_stack(InstrTable& t);
void register_push(InstrTable& t);
void register_log(InstrTable& t);
void register_system(InstrTable& t);

}  // namespace zevm

#pragma once
// keccak.cpp — KECCAK256 (0x20).
//
// Hashes a memory window [offset, offset+size) and pushes the 32-byte digest.
// Gas: 30 base + 6 per 32-byte word + memory expansion. The digest is big-endian
// bytes, byteswapped into the little-endian slot. (A candidate for the ZisK
// Keccak precompile.)

#include "detail.hpp"

#include <cstring>

#include <zeg/keccak.hpp>

#include "evm_mem.hpp"

namespace zevm {

namespace keccak_ops {

constexpr int64_t GAS_KECCAK256      = 30;  // base
constexpr int64_t GAS_KECCAK256_WORD = 6;   // per 32-byte word of input

// 0x20 KECCAK256 — stack: offset (top), size (second). Result replaces size.
bool op_keccak256(EvmState& s, Regs& R) {
    if (R.gas < GAS_KECCAK256) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_KECCAK256;
    if (depth_lt(s, R.top, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    U256* const off_i  = R.top;
    U256* const size_i = R.top + 1;
    const uint64_t off  = mem_arg(off_i[0]);
    const uint64_t size = mem_arg(size_i[0]);

    if (mem_expand(s, R, static_cast<size_t>(off), static_cast<size_t>(size)) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    const int64_t word_cost = num_words(size) * GAS_KECCAK256_WORD;
    if (R.gas < word_cost) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= word_cost;

    const uint8_t* data = size != 0 ? EVMMem::data(static_cast<size_t>(off)) : nullptr;
    const evmc_bytes32 digest = zeg::keccak256_bytes32(data, static_cast<size_t>(size));
    size_i[0] = u256_from_be(digest.bytes);  // BE digest -> LE slot

    ++R.top;  // popped offset; result sits in the old size slot
    ++R.pc;
    return true;
}

}  // namespace


}  // namespace zevm

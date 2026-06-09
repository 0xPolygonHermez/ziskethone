// keccak.cpp — KECCAK256 (0x20).
//
// Hashes a memory window [offset, offset+size) and pushes the 32-byte digest.
// Gas: 30 base + 6 per 32-byte word + memory expansion. The digest is big-endian
// bytes, i.e. the BE stack form. (A candidate for the ZisK Keccak precompile.)

#include "detail.hpp"

#include <cstring>

#include <zeg/keccak.hpp>

#include "evm_mem.hpp"

namespace zevm {

namespace {

constexpr int64_t GAS_KECCAK256      = 30;  // base
constexpr int64_t GAS_KECCAK256_WORD = 6;   // per 32-byte word of input

// 0x20 KECCAK256 — stack: offset (top), size (second). Result replaces size.
bool op_keccak256(EvmState& s) {
    if (s.gas < GAS_KECCAK256) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_KECCAK256;
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const uint32_t off_i  = s.stackPointer;
    const uint32_t size_i = s.stackPointer + 1;
    to_le(s, off_i);
    to_le(s, size_i);
    const uint64_t off  = mem_arg(s.stack[off_i]);
    const uint64_t size = mem_arg(s.stack[size_i]);

    if (EVMMem::expand(static_cast<size_t>(off), static_cast<size_t>(size), &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    const int64_t word_cost = num_words(size) * GAS_KECCAK256_WORD;
    if (s.gas < word_cost) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= word_cost;

    const uint8_t* data = size != 0 ? EVMMem::data(static_cast<size_t>(off)) : nullptr;
    const evmc_bytes32 digest = zeg::keccak256_bytes32(data, static_cast<size_t>(size));
    std::memcpy(&s.stack[size_i], digest.bytes, 32);  // digest is big-endian -> BE form
    s.stackBE[size_i] = kBE;

    ++s.stackPointer;  // popped offset; result sits in the old size slot
    ++s.pc;
    return true;
}

}  // namespace

void register_keccak(InstrTable& t) {
    t[0x20] = &op_keccak256;
}

}  // namespace zevm

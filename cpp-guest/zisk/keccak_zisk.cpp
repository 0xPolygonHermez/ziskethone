// keccak_zisk.cpp — Keccak-256 for the ZisK build, through the EF zkVM accelerator ABI.
//
// Drop-in replacement for evmone's evmone_precompiles/keccak.c. It provides the
// single public symbol the whole guest funnels through:
//
//   union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size)
//
// Every Keccak in the guest bottoms out here — zeg::keccak256_bytes32
// (zeg/keccak.hpp), the direct ethash::keccak256 in contracts.cpp, and the EVM
// KECCAK256 opcode inside evmone. It is one zkvm_keccak256 call: a zkvmcall thunk
// (zkvm_calls.s) that the transpiler turns into a jump to the native .zisk sponge.
// Compiled only into the ZisK target (see CMakeLists.txt).

#include <cstddef>
#include <cstdint>

#include <evmone_precompiles/keccak.h>  // union ethash_hash256, signature
#include "zkvm_accelerators.h"

extern "C" union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size) noexcept {
    union ethash_hash256 hash;
    zkvm_keccak256(data, size, reinterpret_cast<zkvm_keccak256_hash*>(hash.bytes));
    return hash;
}

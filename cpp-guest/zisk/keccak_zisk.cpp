// keccak_zisk.cpp — Keccak-256 for the ZisK build, through the EF zkVM accelerator ABI.
//
// Drop-in replacement for evmone's evmone_precompiles/keccak.c. It provides the
// single public symbol the whole guest funnels through:
//
//   union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size)
//
// Every Keccak in the guest bottoms out here — zeg::keccak256_bytes32
// (zeg/keccak.hpp), the direct ethash::keccak256 in contracts.cpp, and the EVM
// KECCAK256 opcode inside evmone. Swapping this one symbol accelerates them all.
//
// It is one zkvm_keccak256 call: a zkvmcall thunk (zkvm_calls.s) that the
// transpiler turns into a jump to the native .zisk sponge, which runs every
// Keccak-f[1600] on the ZisK precompile. The digest is bit-for-bit the one
// evmone's software sponge computes.
//
// That routine replaces the sponge this file used to run in C on top of a
// keccak-f memo (zeg/keccakf_cache.hpp, removed). The .zisk sponge keeps its
// state at a fixed address and pads with DMA, so it spends far fewer steps
// around each permutation than the C one did. That saves more than the memo did
// by skipping repeated permutations, once the memo's own lookups are paid for.

#include <cstddef>
#include <cstdint>

#include <evmone_precompiles/keccak.h>  // union ethash_hash256, signature

#include "zkvm_accelerators.h"
#include "zeg/fatal.hpp"

// The routine writes the digest straight into `hash`, so the two types must agree on size and
// on the 8-byte alignment zkvm_keccak256_hash requires.
static_assert(sizeof(union ethash_hash256) == sizeof(zkvm_keccak256_hash));
static_assert(alignof(union ethash_hash256) >= alignof(zkvm_keccak256_hash));

extern "C" union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size) noexcept {
    union ethash_hash256 hash;
    // Abort on any non-OK accelerator status rather than return an undefined
    // digest. Unreachable today; a guard against future zisklib changes.
    if (zkvm_keccak256(data, size, reinterpret_cast<zkvm_keccak256_hash*>(&hash)) != ZKVM_EOK) {
        zeg::fatal("zkvm_keccak256 failed");
    }
    return hash;
}

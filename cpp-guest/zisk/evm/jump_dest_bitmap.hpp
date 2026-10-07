// jump_dest_bitmap.hpp — JUMPDEST analysis on the ZisK EVM precompile.
//
// The ZisK `jump_dest_bitmap` precompile (CSR 0x81C) does in one op what both
// EVM backends otherwise do with a byte-walk loop over every executed contract:
// given bytecode and its length, it writes the JUMPDEST bitmap — ceil(size/64)
// little-endian u64 words, bit i set iff code[i] is a real JUMPDEST (opcode 0x5b
// that is not PUSH immediate data). Bit layout, word count and PUSH-skipping are
// exactly what evmone's BitsetSpan and zevm's build_jumpdest_bitset already
// produce (reference impl: zisk precompiles/evm/src/jump_dest_bitmap.rs), so it
// is a drop-in for both.
//
// Cost: EVM_JUMP_DEST_BITMAP_COST = DMA_64_ALIGNED_COST = 77 per 64 bytes of
// code, i.e. ~1.1x a single main-step (MAIN_COST = 68) per 64 code bytes,
// against the software walk's ~1 step per instruction boundary.
//
// Invocation follows the same csrs+add marker pattern as the DMA mem* thunks
// (zisk/dma/memcpy.s) and ziskos' `ziskos_jump_dest_bitmap!` macro:
//
//     csrs 0x81c, <src>        # marker: bytecode pointer
//     add  x0, <dst>, <size>   # bitmap pointer, byte count
//
// The transpiler (riscv2zisk) recognizes the pair and lowers it to one
// jump_dest_bitmap op with params (bitmap, bytecode, count). Both instructions
// must stay adjacent, hence one asm block.
//
// Dual mode, like bigint/backend.hpp: the precompile only exists in the ZisK
// build (ZEG_ZISK). Elsewhere — and with -DZEG_JUMPDEST_SW=ON, kept for A/B
// step-count runs against the software walk — this header defines nothing and
// ZEG_JUMPDEST_PRECOMPILE stays undefined, so call sites keep their software
// analysis and the host build remains the independent reference.

#pragma once

#include <cstddef>
#include <cstdint>

#if defined(ZEG_ZISK) && !defined(ZEG_JUMPDEST_SW)

#define ZEG_JUMPDEST_PRECOMPILE 1

namespace zeg::evm {

// True iff the precompile may be called with these arguments. Callers that get
// false must build the bitmap with their own software walk instead.
//
// The preconditions come from ziskos' `ziskos_jump_dest!`
// (zisk ziskos/entrypoint/src/evm/jump_dest.rs); breaking one is not a soundness
// hole, it makes the program UNPROVABLE — the emulator asserts, so the bug
// surfaces there rather than at proving time:
//
//   * `bitmap` and `code` are both 8-byte aligned. The machine reads and writes
//     whole aligned 64-bit words; an unaligned run is not arithmetizable. This is
//     the caller's to check — `code` in particular is often NOT aligned: contract
//     bytecode points straight into the private input buffer at whatever offset
//     the witness put it, and initcode into EVM memory. (evmone's call site
//     analyzes its padded copy, which is allocated aligned, so it passes; zevm's
//     `code` is the raw pointer, so it is the one that really needs this.)
//   * `size > 0`. An empty call spans no bitmap word, so it occupies no row in the
//     AIR while main still claims it, and the operation bus would not balance.
//     There is nothing to compute either, so callers should just return.
//   * `bitmap` holds at least ceil(size/64) words — not checkable from here. The
//     last word is written in full even when the bytecode ends part way into it.
inline bool jump_dest_bitmap_usable(const uint64_t* bitmap, const uint8_t* code, size_t size) {
    // One test for both pointers: OR them, and any of the three low bits set in
    // either address fails the check.
    const uintptr_t addr_bits =
        reinterpret_cast<uintptr_t>(bitmap) | reinterpret_cast<uintptr_t>(code);
    return size != 0 && (addr_bits & 7u) == 0;
}

// Write the JUMPDEST bitmap of code[0..size) into bitmap[0..ceil(size/64)).
// Every word is written, including the zeros — no pre-clearing needed.
//
// Preconditions as above: call `jump_dest_bitmap_usable()` first, and use a
// software walk when it says no.
inline void jump_dest_bitmap(uint64_t* bitmap, const uint8_t* code, size_t size) {
    asm volatile(
        "csrs 0x81c, %[src]\n\t"
        "add  x0, %[dst], %[size]"
        :
        : [src] "r"(code), [dst] "r"(bitmap), [size] "r"(size)
        : "memory");
}

}  // namespace zeg::evm

#endif  // ZEG_ZISK && !ZEG_JUMPDEST_SW

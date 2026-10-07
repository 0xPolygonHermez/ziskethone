// zisk_evm.hpp — ZisK EVM precompiles for the C++ guest.
//
// C++ counterpart of ziskos' `ziskos_jump_dest!`
// (zisk/ziskos/entrypoint/src/evm/jump_dest.rs).
//
// Marker pair, same shape as the DMA ones — the transpiler folds it into one
// jump_dest operation, so the two instructions must stay adjacent:
//
//     csrs 0x81C, src            src = bytecode
//     add  x0, dst, size         dst = bitmap, size = bytecode length
//
// Given bytecode and its length it writes the JUMPDEST bitmap: ceil(size/64)
// little-endian u64 words, bit i set iff code[i] is a real JUMPDEST (a 0x5b
// that is not PUSH immediate data). Every word is written, zeros included, so
// the destination needs no clearing.

#pragma once

#include <cstddef>
#include <cstdint>

#if defined(ZEG_ZISK)

namespace zeg::zisk {

// True iff the precompile may be called with these arguments. A caller that
// gets false must build the bitmap with its own software walk.
//
// The preconditions are ziskos': breaking one is not a soundness hole, it
// leaves the program UNPROVABLE — the emulator asserts, so the bug surfaces
// there rather than at proving time.
//
//   * `bitmap` and `code` are both 8-byte aligned. The machine reads and writes
//     whole aligned 64-bit words; an unaligned run is not arithmetizable. This
//     is the caller's to check, and `code` in particular is often NOT aligned:
//     contract bytecode points straight into the private input buffer at
//     whatever offset the witness put it.
//   * `size > 0`. An empty call spans no bitmap word, so it occupies no row in
//     the AIR while main still claims it, and the operation bus would not
//     balance. There is nothing to compute either, so callers should return.
//   * `bitmap` holds at least ceil(size/64) words — not checkable from here.
inline bool zisk_jump_dest_bitmap_usable(const uint64_t* bitmap, const uint8_t* code,
                                         size_t size) {
    // One test for both pointers: OR them, and any of the three low bits set in
    // either address fails the check.
    const uintptr_t addr_bits =
        reinterpret_cast<uintptr_t>(bitmap) | reinterpret_cast<uintptr_t>(code);
    return size != 0 && (addr_bits & 7u) == 0;
}

// Write the JUMPDEST bitmap of code[0..size) into bitmap[0..ceil(size/64)).
// Preconditions as above: call zisk_jump_dest_bitmap_usable() first.
inline void zisk_jump_dest_bitmap(uint64_t* bitmap, const uint8_t* code, size_t size) {
    asm volatile("csrs 0x81c, %[src]\n\tadd x0, %[dst], %[size]"
                 :
                 : [dst] "r"(bitmap), [src] "r"(code), [size] "r"(size)
                 : "memory");
}

}  // namespace zeg::zisk

#endif  // ZEG_ZISK

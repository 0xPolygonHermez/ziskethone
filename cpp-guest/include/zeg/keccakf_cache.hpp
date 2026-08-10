// keccakf_cache.hpp — memo for the Keccak-f[1600] permutation, looked up by the executor.
//
// The permutation is the unit of cost: one invocation is ~75.6k of ZisK area, against 25
// for an `add`, and it is 42% of a block's proving cost. Two *different* messages that
// share a 136-byte-aligned prefix run identical permutations over it, so there is far more
// to recover here than at the message level: on one measured block 34,168 permutations
// repeat against only 14,530 whole-message repeats.
//
// An earlier version of this file did the whole thing in the guest — fingerprint the state,
// index a set-associative table, compare the ways — and it lost on every block. Not because
// the hits were not there, but because the guest paid ~9.6k of area for each of 251,853
// probes to find them, and three quarters of all permutations belong to MPT nodes that never
// repeat. The probe, not the miss, was the problem.
//
// So the probe moves out of the proof. `fcall_get_keccakf_cache_index` asks the executor,
// which keeps the same map natively (a hash of the 25 words and an open-addressed table, see
// zisk's lib-c/c/src/keccakf_cache and ziskos' zisklib::keccakf_cache); it costs the guest
// three instructions and nothing else, because the 25 state words a free-input call reads
// are read by the executor, outside the proven memory operations. What is left in the guest
// is only what soundness requires: a range check and one 200-byte compare.
//
// SOUNDNESS. The index is a *hint*: a free-input call is not verified by the VM, and a
// wrong or hostile answer must not be able to change a digest. Two checks make that so, and
// neither trusts the executor:
//
//   1. The index must be inside the part of `g_table` this execution has already written.
//      That also subsumes the not-found sentinel, which is ~0 and therefore never in range.
//   2. The entry it points at must hold *this* state, compared word for word.
//
// Only then is its output used, and that output was produced by this same execution running
// the real permutation. Keccak-f is a function, so equal inputs have equal outputs; a bad
// hint costs a wasted compare and never a wrong answer. The table is published in the right
// order for that to hold under a hint that arrives early: `g_used` — the only thing that
// makes an entry reachable — moves after both halves are written.
//
// Entries own the bytes they compare against. Keying on a caller's pointer would be unsound,
// because the sponge permutes a stack buffer that the next call reuses, so a later state
// landing at the same address would compare equal to a stale entry and take an output
// computed from bytes long gone.

#pragma once

#include <cstddef>
#include <cstdint>

#include "zeg/zisk_dma.hpp"  // DMA markers on ZisK, <cstring> off it

#if !defined(ZEG_ZISK)
#error "keccakf_cache.hpp is the ZisK path: it issues fcalls and the Keccak-f precompile"
#endif

namespace zeg::keccakf_cache {

inline constexpr std::size_t kLanes = 25;               // Keccak-f[1600]
inline constexpr std::size_t kStateBytes = kLanes * 8;  // 200

// What the lookup returns when the executor has never seen this state. Reserved by the
// fcall, so it is never a real index. The range check below rejects it on its own — this is
// here to name the value, not because anything compares against it.
inline constexpr uint64_t kNotFound = ~uint64_t{0};

// One entry per *distinct* state, appended in the order they are first permuted, and the
// index the executor hands back is a position in here. No sets, no ways, no eviction: the
// executor's table is exact, so the guest side needs no geometry, and every distinct state
// that fits gets a slot instead of fighting for one.
//
// 262144 x 400 B = 105 MB. Sized against the blocks that stress it rather than the average
// ones: the busiest measured block runs 421,440 permutations, and the ~262k the old
// set-associative table could hold recovered 261,671 of them, which puts the distinct count
// comfortably under this capacity. Above it the cache simply stops growing (see below), so
// overshooting costs proving speed, never correctness.
//
// This is also *less* memory than the 134 MB the set-associative version needed for the same
// reach, which matters: the zevm backend already carries ~310 MB of its own .bss and the
// guest has 512 MB of RAM.
inline constexpr std::size_t kEntries = 262144;

namespace detail {

struct alignas(8) Entry {
    uint64_t in[kLanes];   // the state as it was before the permutation
    uint64_t out[kLanes];  // and after it
};
static_assert(sizeof(Entry) == 2 * kStateBytes, "Entry must be exactly the two states");

inline Entry g_table[kEntries];

// Entries written so far, and the bound every hint is checked against. Lives in .bss, so an
// execution starts with an empty table and every index out of range.
inline uint64_t g_used = 0;

// ZisK Keccak-f[1600] precompile. CSR 0x800 takes a pointer (in a register) to the 25-word
// state and permutes it in place. Matches ziskos' `ziskos_syscall!` (`csrs {port}, {value}`).
inline void syscall_keccakf(uint64_t* state /* &state[25] */) noexcept {
    register unsigned long a0 asm("a0") = reinterpret_cast<unsigned long>(state);
    asm volatile("csrs 0x800, %0" : : "r"(a0) : "memory");
}

// The two free-input calls, in the encoding ziskos' `ziskos_fcall_param!` / `ziskos_fcall!` /
// `ziskos_fcall_get` macros produce:
//
//   csrs  0x8F0+p, rs1   push a parameter; p selects how many words, 0 = the register value
//                        itself, 8 = the 25 words at that address (zisk's fcall.rs table)
//   csrwi 0x8C0, id      run fcall `id` over the parameters pushed since the last one
//   csrr  rd, 0xFFE      read the next result word
//
// The parameter register must not be x0 — the transpiler reads `csrrs x0, csr, x0` as a nop
// rather than as a parameter push — hence the pinned `a0` rather than a plain "r", which the
// compiler is free to satisfy with the zero register when it knows the value is 0.
inline constexpr int kFcallSetIndexId = 24;  // FCALL_SET_KECCAKF_CACHE_INDEX_ID
inline constexpr int kFcallGetIndexId = 25;  // FCALL_GET_KECCAKF_CACHE_INDEX_ID

// Ask the executor to file the input state of the *next* permutation it runs under `index`.
inline void fcall_set_index(uint64_t index) noexcept {
    register unsigned long a0 asm("a0") = static_cast<unsigned long>(index);
    asm volatile("csrs 0x8F0, %0\n\t"  // one parameter, by value: the index
                 "csrwi 0x8C0, 24"     // = kFcallSetIndexId
                 :
                 : "r"(a0)
                 : "memory");
}

// Index `state` was filed under, or kNotFound. Believing this without the checks in
// `zisk_keccakf` would be a soundness hole, not just a bug.
inline uint64_t fcall_get_index(const uint64_t* state /* &state[25] */) noexcept {
    register unsigned long a0 asm("a0") = reinterpret_cast<unsigned long>(state);
    uint64_t index;
    asm volatile("csrs 0x8F8, %[st]\n\t"  // one parameter: the 25 words at [state]
                 "csrwi 0x8C0, 25\n\t"    // = kFcallGetIndexId
                 "csrr %[idx], 0xFFE"     // fcall_get: the index
                 : [idx] "=&r"(index)
                 : [st] "r"(a0)
                 : "memory");
    return index;
}

}  // namespace detail

// Permute `state` in place, reusing the output of an earlier identical permutation when the
// executor knows of one. This is the only Keccak-f the guest should run: it *is* the
// permutation, with the memo folded in.
inline void zisk_keccakf(uint64_t* state /* &state[25] */) noexcept {
    const uint64_t index = detail::fcall_get_index(state);

    // Both halves of the soundness argument, in the order that makes the cheap one reject
    // first: an out-of-range index (which is what kNotFound is) never reaches the compare.
    if (index < detail::g_used &&
        zeg::zisk::zisk_xmemcmp<kStateBytes>(detail::g_table[index].in, state) == 0) {
        zeg::zisk::zisk_xmemcpy<kStateBytes>(state, detail::g_table[index].out);
        return;
    }

    if (detail::g_used == kEntries) {
        // Full: keep permuting, just stop remembering. Filing more would mean evicting, and
        // an evicted slot only ever produces hints that fail the compare above.
        detail::syscall_keccakf(state);
        return;
    }

    detail::Entry& e = detail::g_table[detail::g_used];
    zeg::zisk::zisk_xmemcpy<kStateBytes>(e.in, state);
    detail::fcall_set_index(detail::g_used);
    detail::syscall_keccakf(state);
    zeg::zisk::zisk_xmemcpy<kStateBytes>(e.out, state);
    // Published last: this is what puts the entry in range, so it must not move until both
    // halves are there.
    ++detail::g_used;
}

}  // namespace zeg::keccakf_cache

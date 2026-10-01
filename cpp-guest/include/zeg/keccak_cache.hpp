// keccak_cache.hpp — memo for repeated Keccak-256 preimages.
//
// A Keccak-f permutation is the most expensive thing the guest does: ~75.6k of
// ZisK area against 25 for an `add`, and 42% of a block's proving cost. So
// recognising work already done is worth a great deal of ordinary work.
//
// This memoizes whole keccak256 CALLS, keyed on the message. Memoizing the
// PERMUTATION instead was measured and is worse everywhere — see the note at
// the bottom of this file, because the reason is not obvious and is the whole
// justification for the length cap below.
//
// SOUNDNESS. The fingerprint is not a hash in the security sense and does not
// need to be: it only picks which slot to look in. A cached digest is returned
// ONLY after `memcmp` confirms that the stored preimage is byte-for-byte the
// input we were asked about, and Keccak is a function, so equal preimages have
// equal digests. A fingerprint collision therefore costs a wasted compare,
// never a wrong answer, and the same holds if the fingerprint is outright bad.
//
// The other half of that argument is that the cache OWNS the bytes it compares
// against. Keying on the caller's pointer would be unsound: the RLP scratch
// buffers the MPT hashes from get reused constantly, so a later input landing
// at the same address would compare equal to a stale entry and take a digest
// computed from bytes that are no longer there. Every entry copies its
// preimage in.

#pragma once

#include <cstddef>
#include <cstdint>

#include "zeg/zisk_dma.hpp"  // DMA markers on ZisK, <cstring> off it

namespace zeg::keccak_cache {

// Only inputs in [8, 64] bytes are cached, and the upper bound is the single
// most important number in this file — not for what it admits, but for what it
// turns away. 15.3% of keccak calls repeat and 99.6% of those repeats are 64
// bytes or shorter: account addresses, storage slot positions, and the
// `key || slot` preimages Solidity builds for every mapping access. Everything
// longer is an MPT node or contract code, hashed once each and never repeated —
// three quarters of all permutations, and declining to probe for them is what
// makes this pay. Raising the cap to 136 or 512 bytes catches 38 and 51 more
// repeats out of ~14.5k while adding thousands of probes.
//
// The lower bound just keeps the fingerprint free of a partial-word case;
// inputs under 8 bytes are a handful per block.
inline constexpr std::size_t kMinLen = 8;
inline constexpr std::size_t kMaxLen = 64;

// Two ways of 262144 sets, entries padded to 128 bytes so a set is 256 and the
// index is a shift: 64 MB, against ~500 MB of guest RAM.
//
// Sized for the blocks that actually need it, which are not the average ones.
// A quiet block hashes ~95k times with only ~14.5k repeats, and 1024 slots
// already capture 88% of those — measuring only such a block is how this table
// was first sized at 1024, and it was wrong by two orders of magnitude. A busy
// block runs 421k permutations with 331k cacheable calls, and there the
// geometry dominates everything else:
//
//     geometry            permutations saved, busiest measured block
//      65536 x1  ( 8 MB)  156,399  (37.1%)
//     262144 x1  (32 MB)  226,370  (53.7%)
//    1048576 x1 (128 MB)  249,638  (59.2%)
//     262144 x2  (64 MB)  255,215  (60.6%)
//
// Two ways beat a direct-mapped table four times as large, at half its memory,
// which is what a second way is for: the misses left at this size are conflicts,
// not capacity. It is nearly free here because the replacement needs no data
// movement — see `aux` below.
inline constexpr std::size_t kSets = 262144;
inline constexpr std::size_t kWays = 2;

namespace detail {

// See the same idiom in keccak_zisk.cpp: message bytes are at an arbitrary
// address and are read through a uint64_t, so the type has to promise no
// alignment and permit aliasing.
using unaligned_u64 [[gnu::aligned(1), gnu::may_alias]] = uint64_t;

inline uint64_t load_lane(const uint8_t* p) noexcept {
    return *reinterpret_cast<const unaligned_u64*>(p);
}

struct alignas(8) Slot {
    uint64_t len;        // 0 = empty; the table lives in .bss, so it starts so
    uint64_t digest[4];
    uint8_t  key[kMaxLen];
    // Only way 0 uses this, as the set's LRU marker: the way most recently
    // read or written. Replacement evicts the other one, which is exact LRU
    // for two ways and moves no data — the reason a second way costs almost
    // nothing here. It survives an overwrite of way 0 because the write path
    // touches len, key and digest and never this field.
    uint64_t aux;
    uint8_t  pad[128 - 8 - 32 - kMaxLen - 8];
};
static_assert(sizeof(Slot) == 128, "Slot is padded so a set is a power of two");

// Laid out set-major: ways of one set are adjacent, so a probe reads them
// together and the set index is a shift.
inline Slot g_table[kSets * kWays];

// Probing is not free, so it has to earn its place. A hit saves a Keccak
// permutation (~75.6k of ZisK area); a probe costs roughly 7.5k, so the table
// pays above about a 10% hit rate.
//
// Most preimage lengths clear that comfortably, but not always: one measured
// block hashes a flood of distinct 64-byte strings — 107k probes for a 1.1%
// hit rate, which cost more than they saved and made that block 1.3% worse.
// The same length bucket is 26.9% on another block, so this cannot be decided
// once at build time from the length alone. Instead each 8-byte length bucket
// keeps its own recent score and stops probing while it is not paying.
//
// Correctness does not depend on any of this: a gated-off bucket simply
// computes, exactly as if the cache were not there.
//
// The window is long and the threshold sits far below break-even on purpose.
// The two regimes are nowhere near each other — buckets that pay run 20-65%,
// the pathological one runs 0.8% — so the gate only has to tell them apart,
// and every point of margin it takes is a real hit given away. Shorter windows
// are measurably worse: at 1024 calls the decision is noisy enough to shut
// buckets that were paying, costing 1.2 points of hit rate on good blocks
// whatever the threshold. At 16384/3% the good blocks keep their full ungated
// hit rate to the last hit, and the pathological bucket still shuts after its
// first window.
inline constexpr uint32_t kWindow    = 16384;
inline constexpr uint32_t kMinHitPct = 3;

// 64-bit counters, not 32-bit, and the width is the point: these four fields
// are read and written on every cacheable call, and on ZisK a 4-byte access
// costs 122 to read and 193 to write against 16 and 18 for an 8-byte one. The
// uint32_t version of this struct cost 0.22 points of area per block — more
// than the gate was saving.
struct Gate {
    uint64_t calls;   // cacheable calls seen in this window
    uint64_t probes;  // of which actually looked in the table
    uint64_t hits;    // of which were served from it
    uint64_t off;     // 0 = probing — so a zeroed .bss starts out probing
};
inline Gate g_gate[kMaxLen / 8 + 1];

// Fold every 8-byte lane in with a rotate and an xor, then finalize.
//
// The finalizer is not optional garnish, and it is where an earlier version of
// this file went wrong. The index takes the LOW bits of the result, while
// rotate-and-xor leaves its entropy in the high ones, so a single multiply and
// xorshift is not enough to drag it down: on a block whose short preimages are
// mostly 64 bytes, that version scored 3,149 hits against 80,692 for a good
// hash over the same 8,192 slots — 25x worse — and barely improved when the
// table grew, which is the signature of an index that is nearly constant.
// splitmix64's two multiplies fix it and cost about ten instructions against
// the 75.6k of area a hit saves.
//
// The lesson is in how that survived: the mix was validated on one block, whose
// duplicate ceiling is low enough that even a poor index looks fine. A
// multiply-per-lane variant was compared on the same single block, matched, and
// was rejected as too dear — it is just as broken, for the same reason.
inline uint64_t fingerprint(const uint8_t* d, std::size_t n) noexcept {
    uint64_t h = n;
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        h = ((h << 11) | (h >> 53)) ^ load_lane(d + i);
    }
    if (i != n) {  // n >= 8 here, so the last full lane overlaps what we read
        h = ((h << 11) | (h >> 53)) ^ load_lane(d + n - 8);
    }
    h ^= h >> 30;  h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27;  h *= 0x94d049bb133111ebULL;
    return h ^ (h >> 31);
}

}  // namespace detail

// Compute keccak256(data[0..size)) into out[0..4), reusing a cached digest when
// this exact byte sequence was hashed before. `compute(out, data, size)` is
// called on a miss and must be the real thing.
template <typename Compute>
inline void memoized(uint64_t* out, const uint8_t* data, std::size_t size,
                     Compute compute) {
    if (size < kMinLen || size > kMaxLen) {
        compute(out, data, size);
        return;
    }

    detail::Gate& g = detail::g_gate[size / 8];
    // While a bucket is gated off, keep sampling one call in sixteen, so a
    // block that changes character can re-open it. The sampled rate reads low
    // (only the sampled calls populate the table), which biases towards staying
    // off — the cheap direction to be wrong in.
    const bool probe = g.off == 0 || (g.calls & 15u) == 0;
    ++g.calls;

    if (probe) {
        ++g.probes;
        detail::Slot* const set =
            &detail::g_table[(detail::fingerprint(data, size) & (kSets - 1)) * kWays];

        // `len` first: it rejects most ways without touching the preimage, and
        // it is what makes an empty way (len 0) miss.
        std::size_t way = kWays;
        for (std::size_t w = 0; w < kWays; ++w) {
            if (set[w].len == size &&
                zeg::zisk::zisk_memcmp(set[w].key, data, size) == 0) {
                way = w;
                break;
            }
        }

        if (way != kWays) {
            zeg::zisk::zisk_xmemcpy<32>(out, set[way].digest);
            set[0].aux = way;  // most recently used
            ++g.hits;
        } else {
            compute(out, data, size);
            // Evict the way that was not the last one used — exact LRU for two
            // ways, and it moves nothing: the victim is simply overwritten in
            // place, and `aux` lives in way 0's padding, which this write does
            // not touch.
            const std::size_t victim = set[0].aux ? 0u : 1u;
            zeg::zisk::zisk_memcpy(set[victim].key, data, size);
            zeg::zisk::zisk_xmemcpy<32>(set[victim].digest, out);
            set[victim].len = size;  // published last: a half-written entry is never live
            set[0].aux = victim;
        }
    } else {
        compute(out, data, size);
    }

    if (g.calls >= detail::kWindow) {
        // Score against the probes actually made, not the calls seen, so the
        // arithmetic means the same thing in both states.
        g.off = (g.hits * 100u < g.probes * uint64_t{detail::kMinHitPct}) ? 1u : 0u;
        g.calls = g.probes = g.hits = 0;
    }
}

// ---------------------------------------------------------------------------
// Why not memoize the permutation instead?
//
// It finds more: two DIFFERENT messages sharing a 136-byte-aligned prefix run
// identical permutations over it, which no message-keyed table can see. On
// block 25701329 that is 34,168 repeated permutations against 14,530 repeated
// messages, 2.25x as many. It was built (zeg/keccakf_cache.hpp), verified, and
// measured, and it loses on every block:
//
//     block          no cache      by message      by permutation
//     25701329   43,970,332,389    -1.88%          +0.44%
//     25710992   40,258,776,489   -18.65%         -15.87%
//     25713690   53,522,828,394   -33.21%         -28.13%
//
// The cost per probe is comparable once an 8-byte tag filters the 200-byte
// compare (9.6k against 7.5k). What sinks it is the number of probes: 251,853
// against 35,895, because a permutation-keyed table cannot decline. By the time
// you are looking at a 200-byte state, the fact that it belongs to a 428-byte
// MPT node which will never repeat has been thrown away — and those are three
// quarters of all permutations. The cheap filter lives at the message level and
// descending below it destroys it. A gate that shuts during the MPT phase was
// tried too: it rescues one block and costs another 18 points.
// ---------------------------------------------------------------------------

}  // namespace zeg::keccak_cache

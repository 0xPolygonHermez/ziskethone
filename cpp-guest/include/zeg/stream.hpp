// Low-level helpers for reading the ZisK guest input stream.
//
// The stream is a `const uint8_t*` into the private-input buffer. It must
// stay 8-byte aligned at all times: every fixed-size field is a multiple
// of 8 bytes and every variable-length blob is followed by zero padding
// up to the next 8-byte boundary. The helpers below enforce that invariant
// at the read sites and let the optimiser lower aligned 8-byte loads to a
// single instruction even on strict-alignment ISAs (notably RISC-V).

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>  // std::assume_aligned

#include "zeg/fatal.hpp"

namespace zeg {

// One-past-the-end of the input buffer, set once by run() before any section
// is parsed (see set_stream_end). The readers below abort (zeg::fatal) before
// any read or advance that would cross it, turning a truncated or
// oversized-`count` input into a clean halt instead of an out-of-bounds read (a
// trap on ZisK, a segfault on the host). Robustness only — an OOB read never
// produces a proof. A single-threaded, one-input-per-process guest makes a
// file-scope end safe and keeps every call site unchanged. When unset
// (nullptr, e.g. a direct unit-test caller), the checks are skipped.
inline const uint8_t* g_stream_end = nullptr;

inline void set_stream_end(const uint8_t* end) { g_stream_end = end; }

// Bytes remaining from `cursor` to the input end, or SIZE_MAX if unbounded.
inline uint64_t stream_remaining(const uint8_t* cursor) {
    if (g_stream_end == nullptr) {
        return static_cast<uint64_t>(-1);
    }
    return (cursor <= g_stream_end)
               ? static_cast<uint64_t>(g_stream_end - cursor)
               : 0;
}

// Read a little-endian u64 from `cursor` and advance past it. The cursor
// is 8-byte aligned by the stream invariant; `std::assume_aligned` tells
// the optimiser so, which lets `memcpy(&u64, p, 8)` lower to a single
// load on strict-alignment ISAs (without the hint GCC would emit 8× byte
// loads + 8× byte stores via the stack on RV64IMA).
inline uint64_t read_u64_le(const uint8_t*& cursor) {
    if (stream_remaining(cursor) < 8) {
        fatal("stream: read_u64_le past end of input");
    }
    const auto* aligned = std::assume_aligned<8>(cursor);
    uint64_t v;
    std::memcpy(&v, aligned, sizeof(v));
    cursor += sizeof(v);
    return v;
}

// Read the next u64 without advancing the cursor — used at dispatch
// sites where the decision (e.g. "is the next opcode a NodeR?") depends
// on the value but we may still hand the un-advanced cursor to a child
// routine that re-reads and consumes it.
inline uint64_t peek_u64_le(const uint8_t* cursor) {
    if (stream_remaining(cursor) < 8) {
        fatal("stream: peek_u64_le past end of input");
    }
    const auto* aligned = std::assume_aligned<8>(cursor);
    uint64_t v;
    std::memcpy(&v, aligned, sizeof(v));
    return v;
}

// Advance `cursor` by `n` bytes, aborting if that would cross the input end.
// Use for every variable-length blob / fixed-width field read off the stream
// (replaces a bare `cursor += n`, which could overflow the pointer on a huge
// attacker-supplied `n`).
inline void advance_checked(const uint8_t*& cursor, uint64_t n) {
    if (stream_remaining(cursor) < n) {
        fatal("stream: advance past end of input");
    }
    cursor += n;
}

// Abort unless at least `n` bytes remain from `cursor`, WITHOUT advancing. Use
// before a fixed-width field copy that reads `n` bytes via a bare `cursor += n`
// (which would otherwise bypass the end guard and read past a truncated input).
inline void require_bytes(const uint8_t* cursor, uint64_t n) {
    if (stream_remaining(cursor) < n) {
        fatal("stream: fixed-field read past end of input");
    }
}

// Advance `cursor` to the next 8-byte boundary if the previous chunk's
// `consumed` byte count was not already a multiple of 8.
inline void align_to_u64(const uint8_t*& cursor, uint64_t consumed) {
    const uint64_t pad = (8 - (consumed & 7)) & 7;
    advance_checked(cursor, pad);
}

} // namespace zeg

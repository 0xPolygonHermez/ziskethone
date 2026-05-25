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

namespace zeg {

// Read a little-endian u64 from `cursor` and advance past it. The cursor
// is 8-byte aligned by the stream invariant; `std::assume_aligned` tells
// the optimiser so, which lets `memcpy(&u64, p, 8)` lower to a single
// load on strict-alignment ISAs (without the hint GCC would emit 8× byte
// loads + 8× byte stores via the stack on RV64IMA).
inline uint64_t read_u64_le(const uint8_t*& cursor) {
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
    const auto* aligned = std::assume_aligned<8>(cursor);
    uint64_t v;
    std::memcpy(&v, aligned, sizeof(v));
    return v;
}

// Advance `cursor` to the next 8-byte boundary if the previous chunk's
// `consumed` byte count was not already a multiple of 8.
inline void align_to_u64(const uint8_t*& cursor, uint64_t consumed) {
    const uint64_t pad = (8 - (consumed & 7)) & 7;
    cursor += pad;
}

} // namespace zeg

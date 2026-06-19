// evm_mem.hpp — EVMMem: the static, depth-ping-pong EVM memory manager.
//
// Instead of malloc'ing + zeroing memory per call frame, zevm carves frames out
// of two large, pre-zeroed byte arenas ("zones"). In the ZisK zkVM address
// space is plentiful and zero-init is free, but *writing* (dirtying) memory
// costs proving work — so the manager hands out never-touched (still-zero) space
// whenever it can, and only zeroes ("cleans") bytes when it has to recycle
// previously-dirtied space.
//
// Two zones, picked by call-depth parity (even depth -> zone 0, odd -> zone 1),
// guarantee that a frame and its direct child never share a zone, so a parent's
// live memory is never clobbered by a child.

#pragma once

#include <cstddef>
#include <cstdint>

namespace zevm {

// ----- tunable sizing --------------------------------------------------------
// A zone must hold at least the most memory one frame can address within the gas
// limit (kMaxMemPerTx), and ideally ~the memory a whole block touches before we
// must recycle dirty space (kMemBlockSize is the perf knob: bigger => less
// cleaning). Both are zero-init BSS, so they cost address space, not real pages,
// until actually touched.
inline constexpr size_t kMaxMemPerTx   = size_t(1) << 25;  //  32 MiB per frame
inline constexpr size_t kMemBlockSize  = size_t(1) << 27;  // 128 MiB per zone
inline constexpr size_t kMaxMemHandles = 1024;             // == EVM max call depth

static_assert(kMemBlockSize > kMaxMemPerTx, "a zone must fit at least one tx");

enum class MemError {
    Ok,
    OutOfGas,
};

// Result of a gas-charging memory op: the outcome plus the gas remaining after
// the charge (valid when err == Ok). Returned by value so the caller's
// register-resident gas need never have its address taken — on RISC-V LP64 this
// two-field, <=16-byte struct comes back in a0/a1, with no memory spill (the old
// `int64_t* gas` interface forced a store+load of gas through EvmState per op).
struct MemGas {
    MemError err;
    int64_t  gas;
};

// A live memory region: an absolute pointer to where it starts inside its zone,
// and its current (word-aligned) logical size in bytes. Holding the pointer
// (rather than a zone-relative offset) lets byte access skip the zone-base add.
struct MemHandle {
    uint8_t* start_ptr;
    size_t   size;
};

// Process-wide EVM memory manager. All state and methods are static; there is a
// single implicit instance backed by BSS. Frames are pushed/popped strictly
// LIFO via createMemory()/destroyMemory(), mirroring nested call frames.
class EVMMem {
public:
    // Push a new (empty) frame; returns its handle index == call depth.
    static int  createMemory();
    // Pop the top frame.
    static void destroyMemory();

    // Raw byte-range access within the current frame's memory — the single
    // primitive for every memory opcode (MLOAD/MSTORE do their own 32-byte
    // big-endian conversion; MSTORE8, CALLDATACOPY/CODECOPY/RETURNDATACOPY/MCOPY,
    // KECCAK256 input, RETURN / REVERT / LOG data, ...). Both may grow memory
    // (charging *gas) and return OutOfGas without mutating state if the
    // expansion can't be paid for. A zero-length access never grows memory.
    static MemGas readBytes (size_t addr, uint8_t* dst, size_t len, int64_t gas);
    static MemGas writeBytes(size_t addr, const uint8_t* src, size_t len, int64_t gas);

    // Write a single byte to memory[addr], growing memory (charging *gas) as
    // needed. A leaner path than writeBytes(addr, &b, 1, gas) for MSTORE8: one
    // store instead of a memcpy, and no length handling.
    static MemGas writeByte(size_t addr, uint8_t value, int64_t gas);

    // Grow the current frame so [addr, addr+len) is addressable, charging gas
    // (and cleaning recycled bytes) — the "check_memory" primitive for CALL
    // arg/return regions, RETURN/REVERT, and *COPY opcodes. No-op for len == 0.
    static MemGas expand(size_t addr, size_t len, int64_t gas);

    // Raw pointer to byte `addr` of the current frame's memory. Valid only while
    // this frame is live (until destroyMemory) and only within the already-grown
    // size. Used to point a sub-call's input at memory and to copy its output
    // back — no copy through a temporary.
    static uint8_t* data(size_t addr) { return s_handles[s_cur].start_ptr + addr; }

    // Current frame's memory size in bytes (word-aligned).
    static size_t size();
    // Current top handle index (call depth); -1 when no frame is active.
    static int    depth() { return s_cur; }

private:
    // Grow the current frame so `need_bytes` are addressable, charging gas and
    // cleaning any recycled (dirty) bytes. No-op when already large enough.
    static MemGas ensure(size_t need_bytes, int64_t gas);

    static uint8_t   s_zone[2][kMemBlockSize];   // the two zeroed arenas
    static MemHandle s_handles[kMaxMemHandles];  // one per live frame
    static int       s_cur;                      // top index; -1 == empty
    static size_t    s_firstClean[2];            // bytes >= this are guaranteed zero
};

}  // namespace zevm

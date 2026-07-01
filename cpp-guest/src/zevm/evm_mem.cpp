// evm_mem.cpp — EVMMem implementation. See evm_mem.hpp for the design rationale.

#include "evm_mem.hpp"

#include <cstring>

namespace zevm {

// ----- static storage --------------------------------------------------------
uint8_t   EVMMem::s_zone[2][kMemBlockSize];
MemHandle EVMMem::s_handles[kMaxMemHandles];
int       EVMMem::s_cur = -1;
size_t    EVMMem::s_firstClean[2] = {0, 0};

namespace {

constexpr size_t kWord = 32;

inline size_t round_up_word(size_t n) {
    return (n + (kWord - 1)) & ~(kWord - 1);
}

// EVM memory-expansion cost component for `words` 32-byte words:
//   Cmem(w) = 3*w + w*w/512   (Yellow Paper).
inline int64_t mem_cost(int64_t words) {
    return 3 * words + (words * words) / 512;
}

inline size_t min_size(size_t a, size_t b) { return a < b ? a : b; }

}  // namespace

int EVMMem::createMemory() {
    ++s_cur;
    const int z = s_cur & 1;

    uint8_t* start;
    if (s_firstClean[z] < kMemBlockSize - kMaxMemPerTx) {
        // Clean placement: start in known-zero space so growth needs no zeroing.
        start = s_zone[z] + s_firstClean[z];
    } else if (s_cur >= 2) {
        // Clean space exhausted: recycle just above the same-zone parent. Bytes
        // here may be dirty, so ensure() will clean on growth.
        start = s_handles[s_cur - 2].start_ptr + s_handles[s_cur - 2].size;
    } else {
        // First frame in this zone: start of the arena.
        start = s_zone[z];
    }

    s_handles[s_cur] = MemHandle{start, 0};
    return s_cur;
}

void EVMMem::destroyMemory() {
    --s_cur;
}

MemGas EVMMem::ensure(size_t need_bytes, int64_t gas) {
    MemHandle& h = s_handles[s_cur];
    if (need_bytes <= h.size)
        return {MemError::Ok, gas};

    const size_t new_size = round_up_word(need_bytes);
    if (new_size > kMaxMemPerTx)
        return {MemError::OutOfGas, gas};  // beyond what any frame may address

    // Zone-capacity guard. Same-parity frames stack within one fixed arena
    // (kMemBlockSize): a single frame is capped at kMaxMemPerTx, but many live
    // same-parity frames can cumulatively exhaust the zone. Growing past the
    // arena would memset/memcpy out of bounds (UB / segfault). Treat zone
    // exhaustion as out-of-gas so the guest fails cleanly instead of crashing.
    //
    // Memory cost is quadratic in gas, so within any realistic per-tx gas cap the
    // cumulative footprint stays far below a zone and this never fires on valid
    // blocks (a zone holds ~80M-gas worth of memory even under an adversary-
    // favorable bound; mainnet block limits are ~30-45M, EIP-7825 caps a tx at
    // 16.7M). It only bounds one known adversarial EEST state test,
    // stStaticCall/static_Call1MB1024Calldepth, which spends ~882e9 gas to hold
    // ~1 MiB in each of 1024 simultaneously-live frames (~1 GiB total) — beyond
    // what a fixed zero-init arena can hold, and impossible in a real block. On
    // that one vector zevm returns out-of-gas where evmone (heap memory) succeeds;
    // a documented, real-block-unreachable divergence, not a crash.
    const int    z   = s_cur & 1;
    const size_t off = static_cast<size_t>(h.start_ptr - s_zone[z]);
    if (off + new_size > kMemBlockSize)
        return {MemError::OutOfGas, gas};

    const int64_t old_words = static_cast<int64_t>(h.size / kWord);
    const int64_t new_words = static_cast<int64_t>(new_size / kWord);
    const int64_t delta     = mem_cost(new_words) - mem_cost(old_words);
    if (delta > gas)
        return {MemError::OutOfGas, gas};
    gas -= delta;

    // Clean any newly-exposed bytes that lie in already-dirtied (recycled)
    // space; everything at or above firstClean is already zero. firstClean is a
    // zone-relative offset, so derive the frame's offset from its pointer.
    const size_t exp_start = off + h.size;
    const size_t exp_end   = off + new_size;
    const size_t dirty_end = min_size(exp_end, s_firstClean[z]);
    if (dirty_end > exp_start)
        std::memset(s_zone[z] + exp_start, 0, dirty_end - exp_start);
    if (exp_end > s_firstClean[z])
        s_firstClean[z] = exp_end;

    h.size = new_size;
    return {MemError::Ok, gas};
}

MemGas EVMMem::readBytes(size_t addr, uint8_t* dst, size_t len, int64_t gas) {
    if (len == 0)
        return {MemError::Ok, gas};
    if (addr > kMaxMemPerTx || len > kMaxMemPerTx)
        return {MemError::OutOfGas, gas};
    const MemGas r = ensure(addr + len, gas);
    if (r.err != MemError::Ok)
        return r;
    std::memcpy(dst, s_handles[s_cur].start_ptr + addr, len);
    return r;
}

MemGas EVMMem::writeBytes(size_t addr, const uint8_t* src, size_t len, int64_t gas) {
    if (len == 0)
        return {MemError::Ok, gas};
    if (addr > kMaxMemPerTx || len > kMaxMemPerTx)
        return {MemError::OutOfGas, gas};
    const MemGas r = ensure(addr + len, gas);
    if (r.err != MemError::Ok)
        return r;
    std::memcpy(s_handles[s_cur].start_ptr + addr, src, len);
    return r;
}

MemGas EVMMem::expand(size_t addr, size_t len, int64_t gas) {
    if (len == 0)
        return {MemError::Ok, gas};
    if (addr > kMaxMemPerTx || len > kMaxMemPerTx)
        return {MemError::OutOfGas, gas};
    return ensure(addr + len, gas);
}

MemGas EVMMem::writeByte(size_t addr, uint8_t value, int64_t gas) {
    if (addr > kMaxMemPerTx)
        return {MemError::OutOfGas, gas};
    const MemGas r = ensure(addr + 1, gas);
    if (r.err != MemError::Ok)
        return r;
    s_handles[s_cur].start_ptr[addr] = value;
    return r;
}

size_t EVMMem::size() {
    return s_handles[s_cur].size;
}

}  // namespace zevm

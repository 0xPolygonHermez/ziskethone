#pragma once

// Per-transaction arena.
//
// The ZisK guest's heap is a bump allocator whose free() is a no-op
// (zisk/runtime.cpp), so memory a transaction allocates and drops is still
// gone at the end of the block. A 200M-gas block of 1 KiB RETURNs, nested
// CALLs or TSTOREs fills the ~400 MiB heap that way with data no longer in use.
//
// The tx arena is a second bump region that grows DOWN from the heap top
// while the main heap grows up, so the two share the space without a fixed
// split. It is reset at the start of every transaction. Only state that
// provably dies with the transaction lives in it:
//   * the Journal's entries (checkpoints never span a transaction),
//   * the TransientStorage map (EIP-1153 clears it per transaction),
//   * evmone's per-call output buffers (patch 14; each is copied into the
//     caller's return data / memory, or into Contracts for deployed code).
// Anything kept past the transaction (receipts, logs, table rows, BAL,
// deployed code) stays on the main heap.
//
// Before tx_arena_reset(), every container using TxArenaAllocator must have
// dropped its storage (not just clear()ed), or it would keep pointers into
// memory the next transaction reuses — and must not allocate again until
// after the reset. Even an empty unordered_map allocates buckets in the
// guest (runtime.cpp's _M_next_bkt rounds 0 up to 2), so rebuild one only
// after the reset (TransientStorage::release()/init()). Arena memory is NOT fresh-zero once
// reused, so callers must initialize what they allocate.
//
// On the host the allocator is std::allocator and the reset a no-op; the
// containers still drop their storage per transaction, so the host build
// exercises the same reset logic as the guest.

#include <cstddef>
#include <memory>

#if defined(ZEG_ZISK)
extern "C" void* zeg_tx_arena_alloc(std::size_t size) noexcept;  // zisk/runtime.cpp
extern "C" void  zeg_tx_arena_reset() noexcept;
#endif

namespace zeg {

template <class T>
struct TxArenaAllocator {
    using value_type = T;
    static_assert(alignof(T) <= 16, "the tx arena is 16-byte aligned");

    TxArenaAllocator() noexcept = default;
    template <class U>
    TxArenaAllocator(const TxArenaAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
#if defined(ZEG_ZISK)
        return static_cast<T*>(zeg_tx_arena_alloc(n * sizeof(T)));
#else
        return std::allocator<T>{}.allocate(n);
#endif
    }
    void deallocate(T* p, std::size_t n) noexcept {
#if defined(ZEG_ZISK)
        (void)p; (void)n;  // reclaimed wholesale by tx_arena_reset()
#else
        std::allocator<T>{}.deallocate(p, n);
#endif
    }

    template <class U>
    bool operator==(const TxArenaAllocator<U>&) const noexcept { return true; }
};

// Release everything in the tx arena. Call only after every TxArenaAllocator
// container has dropped its storage and no evmone call result is alive.
inline void tx_arena_reset() noexcept {
#if defined(ZEG_ZISK)
    zeg_tx_arena_reset();
#endif
}

} // namespace zeg

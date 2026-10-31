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
//   * evmone's EVM memory (patch 16; dropped by the VM's release_tx_buffers
//     before the reset). Call outputs and return data are views of it,
//   * the code analysis of CREATE init code (both backends; evmone's in a
//     FrameScratch, so it is reused once the frame returns),
//   * code the transaction deploys (Contracts::insert), until the
//     transaction ends and the code that survived moves to the main heap.
// A system call counts as a transaction (ZiskStateDB::reset_tx_arena).
// Anything else kept past the transaction (receipts, logs, table rows, BAL)
// stays on the main heap.
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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>

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

// LIFO scratch for buffers that live exactly as long as one EVM frame (the
// analysis of CREATE init code, which no cache keeps). Taken from the tx
// arena in chunks; a frame takes a mark, allocates, and rewinds to the mark
// when it returns, so the next frame reuses the bytes. Allocating each
// analysis straight from the arena kept all of them until the transaction
// ended: ~147 KB per CREATE of 128 KiB init code that reverts at once, ~120 MB
// in one 2^24-gas transaction (audit D). Frames nest, so the scratch in use
// is the deepest live chain of them, not their count. Chunks stay with the
// scratch until release() (a rewound chunk serves the next allocation).
// release() before the arena reset; on the host the chunks are heap blocks
// and release() frees them.
class FrameScratch {
    struct Chunk {
        Chunk*      next;  // chunks past the top are free
        std::size_t cap;   // bytes after the header
        std::size_t used;
        uint8_t* data() noexcept { return reinterpret_cast<uint8_t*>(this) + kHeader; }
    };
    static constexpr std::size_t kHeader = (sizeof(Chunk) + 15) & ~std::size_t{15};
    static constexpr std::size_t kChunk  = std::size_t{1} << 20;

    Chunk* head_ = nullptr;
    Chunk* top_  = nullptr;  // chunk holding the newest allocation; null when empty

    static Chunk* new_chunk(std::size_t cap) {
#if defined(ZEG_ZISK)
        void* p = zeg_tx_arena_alloc(kHeader + cap);
#else
        void* p = ::operator new(kHeader + cap);
#endif
        return new (p) Chunk{nullptr, cap, 0};
    }

public:
    struct Mark {
        Chunk*      chunk;
        std::size_t used;
    };

    FrameScratch() = default;
    FrameScratch(const FrameScratch&) = delete;
    FrameScratch& operator=(const FrameScratch&) = delete;
    ~FrameScratch() { release(); }

    Mark mark() const noexcept { return {top_, top_ != nullptr ? top_->used : 0}; }

    // Drop everything allocated since `m` (taken by the frame that is ending;
    // anything newer belonged to frames that already ended).
    void rewind(Mark m) noexcept {
        top_ = m.chunk;
        if (top_ != nullptr) top_->used = m.used;
    }

    // 16-byte aligned, NOT zeroed.
    void* alloc(std::size_t n) {
        n = (n + 15) & ~std::size_t{15};
        if (top_ != nullptr && top_->cap - top_->used >= n) {
            void* p = top_->data() + top_->used;
            top_->used += n;
            return p;
        }
        Chunk* next = top_ != nullptr ? top_->next : head_;
        if (next == nullptr || next->cap < n) {
            Chunk* c = new_chunk(std::max(n, kChunk - kHeader));
            c->next = next;
            (top_ != nullptr ? top_->next : head_) = c;
            next = c;
        }
        next->used = n;
        top_ = next;
        return next->data();
    }

    // Forget every chunk: at each transaction start, before the arena reset.
    void release() noexcept {
#if !defined(ZEG_ZISK)
        for (Chunk* c = head_; c != nullptr;) {
            Chunk* next = c->next;
            ::operator delete(c);
            c = next;
        }
#endif
        head_ = top_ = nullptr;
    }
};

} // namespace zeg

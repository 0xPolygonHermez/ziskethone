/* arena_malloc.cpp — bump allocator + C++ operator new/delete for the
 * Zisk bare-metal guest.
 *
 * Provides malloc / calloc / realloc / free + aligned_alloc /
 * posix_memalign backed by a single monotonically-increasing pointer
 * into the [_kernel_heap_bottom, _kernel_heap_top) region defined by
 * zisk.ld. free() is a no-op (zkVM execution is single-shot — no
 * fragmentation to worry about), but realloc() DOES copy the old data
 * (see comments below; missing this corrupts every growing container).
 *
 * Also overrides the full C++ operator new / delete family, including
 * the C++17 aligned variants taking std::align_val_t — evmone's
 * StackSpace (`alignas(32) uint256 items[1024]`) goes through these.
 *
 * Alignment guarantee: every allocation is at least 16-byte aligned,
 * matching __STDCPP_DEFAULT_NEW_ALIGNMENT__ on rv64 lp64 and
 * _Alignof(max_align_t).
 */
#include <cstddef>
#include <cstring>
#include <new>

extern "C" char _kernel_heap_bottom;
extern "C" char _kernel_heap_top;

/* Eager-initialised pointer constant: the linker resolves
 * &_kernel_heap_bottom at link time, stored in .data as a relocated
 * R_RISCV_64 entry. ziskemu then loads .data and arena_next is live
 * before any global ctor runs — so malloc has no lazy-init branch on
 * the hot path. */
static char *arena_next = &_kernel_heap_bottom;

/* Default alignment for malloc-family allocations. Matches
 * __STDCPP_DEFAULT_NEW_ALIGNMENT__ (16) on rv64 lp64. Any allocation
 * with stricter alignment goes through aligned_malloc(). */
static constexpr std::size_t kDefaultAlign = 16;

/* No OOM check on the hot path: the heap is 510 MB and a single
 * Ethereum block has never exhausted it. Eliminating the compare
 * against &_kernel_heap_top saves one branch per malloc call. If we
 * ever do OOM, the resulting nullptr-or-overrun will surface as a
 * deterministic crash rather than a silent corruption. */
extern "C" __attribute__((hot)) void *malloc(std::size_t size) {
    size = (size + (kDefaultAlign - 1)) & ~(kDefaultAlign - 1);
    char *p = arena_next;
    arena_next += size;
    return p;
}

/* Aligned bump-alloc: advance arena_next to an `alignment`-aligned address
 * before serving. `alignment` must be a power of two. */
static __attribute__((hot)) void *aligned_malloc(std::size_t alignment, std::size_t size) {
    std::size_t addr = reinterpret_cast<std::size_t>(arena_next);
    std::size_t aligned = (addr + alignment - 1) & ~(alignment - 1);
    std::size_t rounded = (size + alignment - 1) & ~(alignment - 1);
    char *p = reinterpret_cast<char *>(aligned);
    arena_next = p + rounded;
    return p;
}

extern "C" void free(void *p) { (void)p; /* no-op */ }

extern "C" __attribute__((hot)) void *calloc(std::size_t n, std::size_t size) {
    std::size_t total = n * size;
    char *p = static_cast<char *>(malloc(total));
    /* memset routes through the Zisk DMA_MEMSET syscall (CSR 0x816) via
     * the asm stub in dma/memset.s — single syscall vs the per-byte
     * store loop that GCC may or may not pattern-match into a call. */
    if (p) std::memset(p, 0, total);
    return p;
}

extern "C" void *realloc(void *old, std::size_t new_size) {
    if (!old) return malloc(new_size);
    if (new_size == 0) { free(old); return nullptr; }
    /* Bump allocator doesn't track sizes. Copy at most
     * min(new_size, arena_next - old). The upper bound is conservative
     * (it includes any other allocations made after `old`) — but the
     * caller only reads OLD_SIZE bytes anyway, so the extra trailing
     * bytes are harmless. The CRITICAL piece is preserving the
     * original allocation's bytes: returning a fresh, uninitialised
     * block here silently corrupts every std::vector growth, every
     * newlib internal table, every container that resizes. */
    void *fresh = malloc(new_size);
    if (!fresh) return nullptr;
    std::size_t old_max = static_cast<std::size_t>(arena_next - static_cast<char *>(old));
    std::size_t copy_n  = (new_size < old_max) ? new_size : old_max;
    std::memcpy(fresh, old, copy_n);
    return fresh;
}

/* aligned_alloc / posix_memalign: standard C11 / POSIX entry points
 * that newlib's internals call from a few places (e.g. _Z*aligned_*).
 * Route through our aligned bump so they obey the same arena. */
extern "C" void *aligned_alloc(std::size_t alignment, std::size_t size) {
    return aligned_malloc(alignment, size);
}

extern "C" int posix_memalign(void **out, std::size_t alignment, std::size_t size) {
    *out = aligned_malloc(alignment, size);
    return *out ? 0 : 12; /* ENOMEM */
}

/* Checkpoint / rewind primitives.
 *
 * Used by the EEST runner in state_transition.cpp::run() to recycle
 * arena memory between independent sub-tests within one JSON file. The
 * 13 MB EIP-2935 history fixture (blockchain_tests/eip2935 ... test_
 * block_hashes_history_at_transition.json) for instance serialises
 * dozens of fork-by-parameter sub-tests; without recycling, our bump
 * arena grows monotonically until we OOM.
 *
 * Contract:
 *   - arena_checkpoint() captures the current bump pointer.
 *   - arena_rewind(cp) restores it. Any allocation made AFTER the
 *     checkpoint becomes garbage; pointers into that range MUST NOT
 *     be dereferenced afterwards.
 *
 * Caller is responsible for ensuring no live references exist into
 * the rewound region. In state_transition.cpp we take the checkpoint
 * AFTER the first sub-test runs to completion, so any function-local
 * statics initialised lazily during that first run live below the
 * checkpoint and survive subsequent rewinds. */
extern "C" void *arena_checkpoint() noexcept {
    return arena_next;
}

extern "C" void arena_rewind(void *checkpoint) noexcept {
    arena_next = static_cast<char *>(checkpoint);
}

/* C++ operator new / delete family.
 * All routed through malloc / free above. With -fno-exceptions the
 * compiler skips the throw-bad_alloc path, so a nullptr return from
 * malloc just propagates back to the caller — which will then crash
 * on the first dereference (acceptable, the heap is 510 MB and we
 * never expect to exhaust it for one Ethereum block). */
void *operator new(std::size_t n)              { return malloc(n); }
void *operator new[](std::size_t n)            { return malloc(n); }
void  operator delete(void *p) noexcept        { free(p); }
void  operator delete[](void *p) noexcept      { free(p); }
void  operator delete(void *p, std::size_t) noexcept   { free(p); }
void  operator delete[](void *p, std::size_t) noexcept { free(p); }

/* Aligned operator new / delete (C++17). Required when a type has
 * an alignment requirement greater than __STDCPP_DEFAULT_NEW_ALIGNMENT__
 * (16 on rv64 lp64) — e.g. evmone's StackSpace which is `alignas(32)
 * uint256 items[1024]`. Without these the compiler emits calls to the
 * libstdc++ stub which on bare-metal returns nullptr, and the caller
 * then writes through that null pointer. */
void *operator new(std::size_t n, std::align_val_t a) {
    return aligned_malloc(static_cast<std::size_t>(a), n);
}
void *operator new[](std::size_t n, std::align_val_t a) {
    return aligned_malloc(static_cast<std::size_t>(a), n);
}
void  operator delete(void *p, std::align_val_t) noexcept       { free(p); }
void  operator delete[](void *p, std::align_val_t) noexcept     { free(p); }
void  operator delete(void *p, std::size_t, std::align_val_t) noexcept   { free(p); }
void  operator delete[](void *p, std::size_t, std::align_val_t) noexcept { free(p); }

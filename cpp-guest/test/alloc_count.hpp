// test/alloc_count.hpp — count host heap allocation on the current thread.
//
// The guest runs under a bump allocator that never frees (zisk/runtime.cpp):
// the cost that matters is the total bytes ever handed out, not the bytes live.
// These counters replace the global operator new/delete so a host unit test can
// assert how many bytes an operation allocates, the host stand-in for the bump
// pointer. Include this in exactly one translation unit (it defines the global
// operators). Not thread-safe; the tests are single-threaded.

#pragma once

#include <cstddef>
#include <cstdlib>
#include <new>

namespace alloc_count {

inline std::size_t g_bytes = 0;   // total bytes ever requested
inline std::size_t g_live = 0;    // currently outstanding bytes
inline std::size_t g_count = 0;   // number of allocations

inline void reset() { g_bytes = 0; g_live = 0; g_count = 0; }

// Bytes allocated while running `fn` (total requested, not peak-live).
template <class Fn>
std::size_t bytes_of(Fn&& fn) {
    const std::size_t before = g_bytes;
    fn();
    return g_bytes - before;
}

}  // namespace alloc_count

// A small header before each block records its size so operator delete can keep
// g_live honest. 16-byte aligned so over-aligned types still land aligned.
namespace alloc_count::detail {
struct Header { std::size_t size; std::size_t pad; };
inline void* alloc(std::size_t n) {
    void* raw = std::malloc(n + sizeof(Header));
    if (raw == nullptr) throw std::bad_alloc();
    auto* h = static_cast<Header*>(raw);
    h->size = n;
    g_bytes += n;
    g_live += n;
    ++g_count;
    return static_cast<void*>(h + 1);
}
inline void free(void* p) noexcept {
    if (p == nullptr) return;
    auto* h = static_cast<Header*>(p) - 1;
    g_live -= h->size;
    std::free(h);
}
}  // namespace alloc_count::detail

void* operator new(std::size_t n) { return alloc_count::detail::alloc(n); }
void* operator new[](std::size_t n) { return alloc_count::detail::alloc(n); }
void  operator delete(void* p) noexcept { alloc_count::detail::free(p); }
void  operator delete[](void* p) noexcept { alloc_count::detail::free(p); }
void  operator delete(void* p, std::size_t) noexcept { alloc_count::detail::free(p); }
void  operator delete[](void* p, std::size_t) noexcept { alloc_count::detail::free(p); }
// Over-aligned forms: malloc gives 16-byte alignment, enough for the guest's
// alignments; the tests don't exercise larger ones.
void* operator new(std::size_t n, std::align_val_t) { return alloc_count::detail::alloc(n); }
void* operator new[](std::size_t n, std::align_val_t) { return alloc_count::detail::alloc(n); }
void  operator delete(void* p, std::align_val_t) noexcept { alloc_count::detail::free(p); }
void  operator delete[](void* p, std::align_val_t) noexcept { alloc_count::detail::free(p); }

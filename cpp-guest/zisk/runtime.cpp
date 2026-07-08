// runtime.cpp — freestanding C/C++ runtime for the cpp-guest ZisK build.
//
// This is the self-contained (no-libziskos) variant: the guest links ONLY
// against this object + the cross toolchain's libgcc-free objects (the
// toolchain's libgcc/libstdc++ are built for rv64imac — the compressed 'c'
// extension ZisK does not run), so we must supply everything libc/libgcc/
// libstdc++ would normally provide and that the guest actually references:
//
//   * the bump allocator backing malloc/realloc/free and operator new,
//   * strlen/strcmp (the mem* family — memcpy/memmove/memset/memcmp — lives in
//     dma/*.s, which routes each through the ZisK DMA precompiles),
//   * the libgcc integer builtins the compiler emits calls to
//     (__bswap{di,si}2, __clzdi2),
//   * loud `halt()` + abort() that stop the emulator,
//   * no-op libc stdio/env stubs (fprintf/getenv/… + _impure_ptr) so the
//     guest's debug-logging sites link without being individually #ifdef'd,
//   * the libstdc++/__cxa ABI symbols the STL pulls in, including the
//     integer-only std::__detail::_Prime_rehash_policy.
//
// Everything here is the minimal set the current builds reference (audited
// across the zevm/evmone backends, the SW-secp variant, and the selftest ELFs
// via nm on the linked ELFs); a new reference shows up as a clear undefined-
// symbol link error — add its stub here. Nothing here may perform
// non-deterministic work — the few trapping stubs must never execute during a
// valid run.

#include <cstddef>
#include <cstdint>
#include <new>
#include <unordered_map>   // declares std::__detail::_Prime_rehash_policy
#include <utility>

#include <zeg/bswap.hpp>   // zeg::bswap64 — the shared byte-swap implementation

extern "C" {

// Linker-script symbols bounding the heap region (see zisk.ld).
extern char _heap_bottom;
extern char _heap_top;

// Abnormal termination (abort / fatal / unreachable stubs). Unlike a clean
// program exit (handled in _start.s via `ecall a7=93`), an abort must FAIL the
// run — there is no "exit with error" syscall on ZisK. So, mirroring _start.s's
// dispatch on marchid == ARCH_ID_ZISK (0xFFFEEEE, true on ziskemu and real ZisK):
//   * pure ZisK  -> execute an illegal `unimp` instruction, trapping the VM /
//                   making proof generation fail (a real abort, not a silent stop);
//   * plain QEMU -> write the magic value to the QEMU exit address.
//
// Exported (zeg_zisk_halt) so stdcxx_stubs.cpp shares this single definition.
extern "C" [[noreturn]] void zeg_zisk_halt() {
    unsigned long marchid;
    asm volatile("csrr %0, marchid" : "=r"(marchid));
    if (marchid == 0xFFFEEEEUL) {
        asm volatile("unimp");                                      // illegal instruction -> trap
    } else {
        *reinterpret_cast<volatile unsigned int *>(0x100000) = 0x5555;  // QEMU exit
    }
    for (;;) {}
}
[[noreturn]] static void halt() { zeg_zisk_halt(); }

// ===========================================================================
// Bump allocator. Single-shot execution: free() is a no-op. ~0.5 GB heap.
// (No calloc: nothing links it — the guest uses malloc and relies on ZisK's
// fresh-RAM-is-zero guarantee where zeroed memory is needed.)
// ===========================================================================
static char *g_next = nullptr;

// memcpy lives in dma/memcpy.s (routed through the ZisK DMA precompile); declare
// it so realloc can use it. -fno-builtin (see zisk/CMakeLists.txt) keeps this an
// out-of-line call to that symbol rather than an inlined byte loop.
void *memcpy(void *dst, const void *src, size_t n);

static inline char *heap_alloc(size_t size) {
    if (!g_next) g_next = &_heap_bottom;
    size = (size + 15) & ~size_t(15);            // 16-byte align (max_align_t)
    char *p = g_next;
    if (p + size > &_heap_top) halt();    // OOM -> stop loudly
    g_next += size;
    return p;
}

void *malloc(size_t size) { return heap_alloc(size); }
void  free(void *) {}

// Bump-allocator realloc: allocate fresh and copy the *requested* new size
// worth (we don't track old sizes; callers only read the bytes they wrote).
void *realloc(void *ptr, size_t size) {
    if (!ptr) return heap_alloc(size);
    char *p = heap_alloc(size);
    // Copy the old block up to the new size via the DMA-accelerated memcpy. Safe
    // because the heap is one contiguous region and old blocks stay mapped; any
    // bytes past the old allocation are fresh zero (the bump arena is untouched).
    memcpy(p, ptr, size);
    return p;
}

void *aligned_alloc(size_t alignment, size_t size) {
    if (!g_next) g_next = &_heap_bottom;
    uintptr_t cur = reinterpret_cast<uintptr_t>(g_next);
    uintptr_t aligned = (cur + (alignment - 1)) & ~(uintptr_t)(alignment - 1);
    g_next = reinterpret_cast<char *>(aligned);
    return heap_alloc(size);
}

// ===========================================================================
// Freestanding str* (no libc). The mem* family (memcpy/memmove/memset/memcmp)
// is provided by dma/*.s, which routes each call through the ZisK DMA precompiles
// (CSR 0x813/0x814/0x816) instead of a byte loop. Only strlen/strcmp stay here —
// there are no DMA str* precompiles.
// ===========================================================================
size_t strlen(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }

int strcmp(const char *a, const char *b) {
    while (*a && (*a == *b)) { ++a; ++b; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

// ===========================================================================
// libgcc integer builtins (rv64ima has no Zbb, so the compiler emits libcalls
// for byte-swap / count-leading-zero idioms it doesn't inline).
// ===========================================================================

// The implementation is the shared zeg::bswap64 (zeg/bswap.hpp); zevm uses that
// inline directly and never routes through this symbol.
uint64_t __bswapdi2(uint64_t x) { return zeg::bswap64(x); }

uint32_t __bswapsi2(uint32_t x) {
    return (x >> 24) | ((x >> 8) & 0xFF00u) | ((x << 8) & 0xFF0000u) | (x << 24);
}

int __clzdi2(uint64_t x) {          // x != 0 (undefined for 0, per libgcc)
    // Binary search instead of a shift loop: 6 mask-tests (~25 steps) flat,
    // where the loop cost grew with the leading-zero count — up to ~190 steps
    // for small values, the common case.
    int n = 0;
    if (!(x & 0xFFFFFFFF00000000ull)) { n += 32; x <<= 32; }
    if (!(x & 0xFFFF000000000000ull)) { n += 16; x <<= 16; }
    if (!(x & 0xFF00000000000000ull)) { n += 8;  x <<= 8; }
    if (!(x & 0xF000000000000000ull)) { n += 4;  x <<= 4; }
    if (!(x & 0xC000000000000000ull)) { n += 2;  x <<= 2; }
    if (!(x & 0x8000000000000000ull)) { n += 1; }
    return n;
}

// ===========================================================================
// Forbidden / abnormal terminations: trap loudly.
// ===========================================================================
void abort() { halt(); }

// ===========================================================================
// No-op libc stdio / env stubs. The guest's debug-logging sites
// (std::fprintf(stderr,…), std::getenv("ZEG_…"), etc.) must LINK; with getenv
// returning null they never fire at runtime. stderr/stdout expand to
// (_impure_ptr->_stdXXX), so provide a dummy _impure_ptr too.
// ===========================================================================
// Layout-compatible enough: newlib's `stderr` macro reads _impure_ptr->_stderr,
// but our stub printf-family ignores the FILE* argument, so any readable
// pointer works. Point _impure_ptr at a zeroed block big enough to cover the
// _stdin/_stdout/_stderr slots near the struct head.
static void *g_impure_storage[64];
void *_impure_ptr = g_impure_storage;

int   fprintf(void *, const char *, ...)     { return 0; }
int   fputc(int c, void *)                   { return c; }
size_t fwrite(const void *, size_t sz, size_t n, void *) { return n; }
char *getenv(const char *)                   { return nullptr; }
int   atoi(const char *)                     { return 0; }

} // extern "C"

// ===========================================================================
// C++ ABI / libstdc++ stubs.
// ===========================================================================
extern "C" {
int  __cxa_atexit(void (*)(void *), void *, void *)  { return 0; }
// Non-reentrant single-thread guards for function-local statics.
int  __cxa_guard_acquire(uint64_t *g) { return !*reinterpret_cast<char *>(g); }
void __cxa_guard_release(uint64_t *g) { *reinterpret_cast<char *>(g) = 1; }
} // extern "C"

namespace std {
// Throw helpers: in a freestanding -fno-exceptions build these are reached only
// on a real error (OOB, bad_alloc); stop loudly rather than UB. Only the ones
// the current builds instantiate are stubbed — a new STL use surfaces as an
// undefined __throw_* at link time; add it here.
void __throw_length_error(const char *) { halt(); }
void __throw_bad_alloc()                { halt(); }
void __throw_bad_array_new_length()     { halt(); }
void terminate() noexcept               { halt(); }
// std::nothrow object referenced by nothrow new.
const nothrow_t nothrow{};
} // namespace std

// __dso_handle: address used by __cxa_atexit registrations. Never dereferenced.
extern "C" { void *__dso_handle = nullptr; }

// operator new/delete wired to the bump allocator. Kept as the complete
// replaceable family (several variants are referenced; the rest are one-line
// companions that keep the ABI surface coherent).
void *operator new(size_t n)                      { return malloc(n); }
void *operator new[](size_t n)                    { return malloc(n); }
void *operator new(size_t n, std::align_val_t a)  { return aligned_alloc(static_cast<size_t>(a), n); }
void *operator new[](size_t n, std::align_val_t a){ return aligned_alloc(static_cast<size_t>(a), n); }
void *operator new(size_t n, const std::nothrow_t&) noexcept   { return malloc(n); }
void *operator new[](size_t n, const std::nothrow_t&) noexcept { return malloc(n); }
void  operator delete(void *) noexcept            {}
void  operator delete[](void *) noexcept          {}
void  operator delete(void *, size_t) noexcept    {}
void  operator delete[](void *, size_t) noexcept  {}
void  operator delete(void *, std::align_val_t) noexcept   {}
void  operator delete[](void *, std::align_val_t) noexcept {}
void  operator delete(void *, size_t, std::align_val_t) noexcept   {}
void  operator delete[](void *, size_t, std::align_val_t) noexcept {}

// ===========================================================================
// std::unordered_map prime rehash policy, integer-only (the libstdc++ default
// uses float load-factor math). Bucket counts only affect hash distribution
// (correctness is independent), so a simple next-prime stepping over a fixed
// table + odd-number primality fallback is sufficient.
// ===========================================================================
namespace {
bool is_prime(std::size_t n) {
    if (n < 2) return false;
    if (n % 2 == 0) return n == 2;
    for (std::size_t i = 3; i * i <= n; i += 2) if (n % i == 0) return false;
    return true;
}
std::size_t next_prime(std::size_t n) {
    static const std::size_t kSmall[] = {
        2, 5, 11, 23, 47, 97, 197, 397, 797, 1597, 3203, 6421, 12853,
        25717, 51437, 102877, 205759, 411527, 823117, 1646237, 3292489,
        6584983, 13169977, 26339969, 52679969, 105359939, 210719881};
    for (std::size_t p : kSmall) if (p >= n) return p;
    std::size_t c = n | 1;
    while (!is_prime(c)) c += 2;
    return c;
}
} // namespace

namespace std::__detail {

std::size_t _Prime_rehash_policy::_M_next_bkt(std::size_t __n) const noexcept {
    const std::size_t __b = next_prime(__n < 2 ? 2 : __n);
    _M_next_resize = __b;                          // grow when element count reaches bucket count (lf<=1)
    return __b;
}

std::pair<bool, std::size_t>
_Prime_rehash_policy::_M_need_rehash(std::size_t __n_bkt, std::size_t __n_elt,
                                     std::size_t __n_ins) const noexcept {
    if (__n_elt + __n_ins > _M_next_resize) {
        std::size_t __min = __n_elt + __n_ins;     // / max_load_factor (>=1 here)
        if (__min >= __n_bkt) {
            std::size_t __want = __min + 1;
            if (__n_bkt * 2 > __want) __want = __n_bkt * 2;
            return {true, _M_next_bkt(__want)};     // updates _M_next_resize
        }
        _M_next_resize = __n_bkt;
        return {false, 0};
    }
    return {false, 0};
}

} // namespace std::__detail

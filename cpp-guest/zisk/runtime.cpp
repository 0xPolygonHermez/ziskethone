// runtime.cpp — freestanding C/C++ runtime for the cpp-guest ZisK build.
//
// This is the self-contained (no-libziskos) variant: the guest links ONLY
// against this object + the cross toolchain's libgcc-free objects, so we must
// supply everything libc/libstdc++ would normally provide and that the guest
// + evmone actually reference:
//
//   * the bump allocator backing malloc/calloc/realloc/free and operator new,
//   * the freestanding mem* family (memcpy/memmove/memset/memcmp/strlen…),
//   * loud `halt()` + abort() that stop the emulator,
//   * no-op libc stdio/env stubs (printf/fprintf/getenv/… + _impure_ptr) so the
//     guest's ~70 debug-logging sites link without being individually #ifdef'd,
//   * the handful of libstdc++/__cxa ABI symbols the STL pulls in.
//
// Nothing here may perform non-deterministic work — the few trapping stubs must
// never execute during a valid run.

#include <cstddef>
#include <cstdint>
#include <new>

extern "C" {

// Linker-script symbols bounding the heap region (see zisk.ld).
extern char _kernel_heap_bottom;
extern char _kernel_heap_top;

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
// ===========================================================================
static char *g_next = nullptr;

static inline char *heap_alloc(size_t size) {
    if (!g_next) g_next = &_kernel_heap_bottom;
    size = (size + 15) & ~size_t(15);            // 16-byte align (max_align_t)
    char *p = g_next;
    if (p + size > &_kernel_heap_top) halt();    // OOM -> stop loudly
    g_next += size;
    return p;
}

void *malloc(size_t size) { return heap_alloc(size); }
void  free(void *) {}

void *calloc(size_t n, size_t size) {
    size_t total = n * size;
    char *p = heap_alloc(total);
    for (size_t i = 0; i < total; ++i) p[i] = 0;
    return p;
}

// Bump-allocator realloc: allocate fresh and copy the *requested* new size
// worth (we don't track old sizes; callers only read the bytes they wrote).
void *realloc(void *ptr, size_t size) {
    if (!ptr) return heap_alloc(size);
    char *p = heap_alloc(size);
    // Copy conservatively from the old block up to the new size. Safe because
    // the heap is one contiguous region and old blocks stay mapped.
    const char *src = static_cast<const char *>(ptr);
    for (size_t i = 0; i < size; ++i) p[i] = src[i];
    return p;
}

void *aligned_alloc(size_t alignment, size_t size) {
    if (!g_next) g_next = &_kernel_heap_bottom;
    uintptr_t cur = reinterpret_cast<uintptr_t>(g_next);
    uintptr_t aligned = (cur + (alignment - 1)) & ~(uintptr_t)(alignment - 1);
    g_next = reinterpret_cast<char *>(aligned);
    return heap_alloc(size);
}

// ===========================================================================
// Freestanding mem* / str* (no libc). Simple, correct, byte-at-a-time.
// ===========================================================================
void *memcpy(void *dst, const void *src, size_t n) {
    auto *d = static_cast<unsigned char *>(dst);
    auto *s = static_cast<const unsigned char *>(src);
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}
void *memmove(void *dst, const void *src, size_t n) {
    auto *d = static_cast<unsigned char *>(dst);
    auto *s = static_cast<const unsigned char *>(src);
    if (d < s) { for (size_t i = 0; i < n; ++i) d[i] = s[i]; }
    else       { for (size_t i = n; i-- > 0;) d[i] = s[i]; }
    return dst;
}
void *memset(void *dst, int c, size_t n) {
    auto *d = static_cast<unsigned char *>(dst);
    for (size_t i = 0; i < n; ++i) d[i] = static_cast<unsigned char>(c);
    return dst;
}
int memcmp(const void *a, const void *b, size_t n) {
    auto *x = static_cast<const unsigned char *>(a);
    auto *y = static_cast<const unsigned char *>(b);
    for (size_t i = 0; i < n; ++i) { if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1; }
    return 0;
}
size_t strlen(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }

// ===========================================================================
// Forbidden / non-deterministic operations: trap loudly.
// ===========================================================================
int  _getentropy(void *, size_t) { halt(); }
int  getentropy(void *, size_t)  { halt(); }
void abort()                     { halt(); }
void __assert_func(const char *, int, const char *, const char *) { halt(); }

// ===========================================================================
// No-op libc stdio / env stubs. The guest's debug-logging sites
// (std::fprintf(stderr,…), std::getenv("ZEG_…"), etc.) must LINK; with getenv
// returning null they never fire at runtime. stderr/stdout expand to
// (_impure_ptr->_stdXXX), so provide a dummy _impure_ptr too.
// ===========================================================================
struct __dummy_file { int _unused; };
static __dummy_file g_dummy_files[3];
// Layout-compatible enough: newlib's `stderr` macro reads _impure_ptr->_stderr,
// but our stub printf-family ignores the FILE* argument, so any readable
// pointer works. Point _impure_ptr at a zeroed block big enough to cover the
// _stdin/_stdout/_stderr slots near the struct head.
static void *g_impure_storage[64];
void *_impure_ptr = g_impure_storage;

int   printf(const char *, ...)              { return 0; }
int   fprintf(void *, const char *, ...)     { return 0; }
int   snprintf(char *s, size_t n, const char *, ...) { if (n) s[0] = 0; return 0; }
int   sprintf(char *s, const char *, ...)    { if (s) s[0] = 0; return 0; }
int   fputs(const char *, void *)            { return 0; }
int   puts(const char *)                     { return 0; }
int   fputc(int c, void *)                   { return c; }
int   putchar(int c)                         { return c; }
size_t fwrite(const void *, size_t sz, size_t n, void *) { return n; }
int   fflush(void *)                         { return 0; }
char *getenv(const char *)                   { return nullptr; }
int   atoi(const char *)                     { return 0; }

} // extern "C"

// ===========================================================================
// C++ ABI / libstdc++ stubs.
// ===========================================================================
extern "C" {
void __cxa_pure_virtual()                            { halt(); }
int  __cxa_atexit(void (*)(void *), void *, void *)  { return 0; }
void __cxa_finalize(void *)                          {}
// Non-reentrant single-thread guards for function-local statics.
int  __cxa_guard_acquire(uint64_t *g) { return !*reinterpret_cast<char *>(g); }
void __cxa_guard_release(uint64_t *g) { *reinterpret_cast<char *>(g) = 1; }
void __cxa_guard_abort(uint64_t *)    {}
} // extern "C"

namespace std {
// Throw helpers: in a freestanding -fno-exceptions build these are reached only
// on a real error (OOB, bad_alloc); stop loudly rather than UB.
void __throw_length_error(const char *) { halt(); }
void __throw_bad_alloc()                { halt(); }
void __throw_out_of_range(const char *) { halt(); }
void __throw_out_of_range_fmt(const char *, ...) { halt(); }
void __throw_bad_array_new_length()     { halt(); }
void __throw_logic_error(const char *)  { halt(); }
void __throw_bad_variant_access(const char *) { halt(); }
void __throw_bad_optional_access()      { halt(); }
void __throw_system_error(int)          { halt(); }
void terminate() noexcept               { halt(); }
// std::nothrow object referenced by nothrow new.
const nothrow_t nothrow{};
} // namespace std

// __dso_handle: address used by __cxa_atexit registrations. Never dereferenced.
extern "C" { void *__dso_handle = nullptr; }

// operator new/delete wired to the bump allocator.
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

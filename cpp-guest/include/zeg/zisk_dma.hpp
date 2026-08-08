// zisk_dma.hpp — ZisK DMA precompiles for the C++ guest.
//
// C++ counterpart of ziskos' `ziskos_memcpy!` / `ziskos_memcmp!` /
// `ziskos_memset!` / `ziskos_inputcpy!` (zisk/ziskos/entrypoint/src/dma.rs).
// Same instruction pairs, same CSR numbers; this is where a C++ caller reaches
// the precompile directly instead of going through the libc symbol and its
// dma/*.s thunk.
//
// The transpiler folds a `csrs 0x81x, …` marker plus the `add`/`addi` that
// follows into ONE operation, x86-`rep`-style. The two instructions must stay
// adjacent, hence one asm block each — never split them.
//
// The `x` prefix means eXtended: the size travels in the instruction immediate
// rather than through memory, and that is not a cosmetic difference:
//
//   csrs 0x813,src ; addi x0,dst,IMM   -> dma_xmemcpy: ONE zisk instruction
//   csrs 0x813,src ; add  x0,dst,reg   -> dma_memcpy:  TWO, the first *writes*
//                                         the count to EXTRA_PARAMS_ADDR
//
// so prefer the `x` form whenever the size is a compile-time constant. It is a
// template parameter because inline asm needs a constant expression for the
// immediate — the C++ equivalent of ziskos matching on `$size:literal`.
//
// Sizes for the `x` forms must fit a signed 12-bit immediate (<= 2047); the
// static_assert says so at the call site rather than letting the assembler
// complain about an instruction it cannot encode.

// Callable from code shared with the host build: outside ZisK the same names
// forward to the standard functions, so a call site does not need an #if. The
// point of the wrappers is that a compile-time size reaches the precompile as an
// immediate, which the plain libc call never can.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#if !defined(ZEG_ZISK)

namespace zeg::zisk {

inline void zisk_memcpy(void* dst, const void* src, size_t size) { std::memcpy(dst, src, size); }
template <size_t Size>
inline void zisk_xmemcpy(void* dst, const void* src) { std::memcpy(dst, src, Size); }

inline int64_t zisk_memcmp(const void* a, const void* b, size_t size) { return std::memcmp(a, b, size); }
template <size_t Size>
inline int64_t zisk_xmemcmp(const void* a, const void* b) { return std::memcmp(a, b, Size); }

template <size_t Size, uint8_t Fill = 0>
inline void zisk_xmemset(void* dst) { std::memset(dst, Fill, Size); }
template <uint8_t Fill = 0>
inline void zisk_xmemset(void* dst, size_t size) { std::memset(dst, Fill, size); }

}  // namespace zeg::zisk

#else

namespace zeg::zisk {

// Largest count an `addi` immediate can carry.
inline constexpr size_t kDmaMaxImm = 2047;

// ---------------------------------------------------------------- memcpy ----

// memcpy(dst, src, size), size in a register.
inline void zisk_memcpy(void* dst, const void* src, size_t size) {
    asm volatile("csrs 0x813, %[src]\n\tadd x0, %[dst], %[size]"
                 :
                 : [dst] "r"(dst), [src] "r"(src), [size] "r"(size)
                 : "memory");
}

// memcpy with a compile-time size: one zisk instruction.
template <size_t Size>
inline void zisk_xmemcpy(void* dst, const void* src) {
    static_assert(Size <= kDmaMaxImm, "zisk_xmemcpy: size must fit a 12-bit immediate");
    asm volatile("csrs 0x813, %[src]\n\taddi x0, %[dst], %[size]"
                 :
                 : [dst] "r"(dst), [src] "r"(src), [size] "I"(Size)
                 : "memory");
}

// ---------------------------------------------------------------- memcmp ----

// memcmp(a, b, size) -> byte_a - byte_b at the first difference, 0 if equal.
// The result register rides on the marker's `csrrs`: putting it on the trailing
// `add` instead is the transpiler's deprecated encoding and it says so on every
// run.
inline int64_t zisk_memcmp(const void* a, const void* b, size_t size) {
    int64_t result;
    asm volatile("csrrs %[res], 0x814, %[src]\n\tadd x0, %[dst], %[size]"
                 : [res] "=r"(result)
                 : [dst] "r"(a), [src] "r"(b), [size] "r"(size)
                 : "memory");
    return result;
}

// memcmp with a compile-time size: one zisk instruction.
template <size_t Size>
inline int64_t zisk_xmemcmp(const void* a, const void* b) {
    static_assert(Size <= kDmaMaxImm, "zisk_xmemcmp: size must fit a 12-bit immediate");
    int64_t result;
    asm volatile("csrrs %[res], 0x814, %[src]\n\taddi x0, %[dst], %[size]"
                 : [res] "=r"(result)
                 : [dst] "r"(a), [src] "r"(b), [size] "I"(Size)
                 : "memory");
    return result;
}

// ---------------------------------------------------------------- memset ----
//
// Only the eXtended form exists: the fill byte has to be an instruction
// immediate, so it is always a template parameter. A run-time fill value has no
// marker at all and must go through the libc `memset` (whose thunk pays a
// 256-entry jump table to turn the byte into an immediate).

// memset(dst, Fill, Size), both compile-time: csrsi 0x816,2 + two addi.
template <size_t Size, uint8_t Fill = 0>
inline void zisk_xmemset(void* dst) {
    static_assert(Size <= kDmaMaxImm, "zisk_xmemset: size must fit a 12-bit immediate");
    asm volatile("csrsi 0x816, 2\n\taddi x0, %[dst], %[size]\n\taddi x0, %[dst], %[fill]"
                 :
                 : [dst] "r"(dst), [size] "I"(Size), [fill] "I"(int(Fill))
                 : "memory");
}

// memset(dst, Fill, size) with the size in a register.
template <uint8_t Fill = 0>
inline void zisk_xmemset(void* dst, size_t size) {
    asm volatile("csrs 0x816, %[dst]\n\taddi x0, %[size], %[fill]"
                 :
                 : [dst] "r"(dst), [size] "r"(size), [fill] "I"(int(Fill))
                 : "memory");
}

// -------------------------------------------------------------- inputcpy ----
//
// Copies free-input data (an fcall result) straight into memory. One pointer:
// it is both the marker operand and the `add` source, exactly as in ziskos.
// The destination needs no initialization.

inline void zisk_inputcpy(void* dst, size_t size) {
    asm volatile("csrs 0x815, %[dst]\n\tadd x0, %[dst], %[size]"
                 :
                 : [dst] "r"(dst), [size] "r"(size)
                 : "memory");
}

template <size_t Size>
inline void zisk_xinputcpy(void* dst) {
    static_assert(Size <= kDmaMaxImm, "zisk_xinputcpy: size must fit a 12-bit immediate");
    asm volatile("csrs 0x815, %[dst]\n\taddi x0, %[dst], %[size]"
                 :
                 : [dst] "r"(dst), [size] "I"(Size)
                 : "memory");
}

}  // namespace zeg::zisk

#endif  // ZEG_ZISK

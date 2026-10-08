// zisk_dma.hpp — memory operations for the C++ guest, on ZisK through the ZisK
// memory ABI (zkvm_mem.h): each is one DMA precompile, inlined by the ABI header
// (a marker the transpiler folds into the DMA op), so the guest never issues the
// precompile CSRs itself.
//
// The names keep the shape of the old direct DMA wrappers, so call sites did not
// change: the `x` forms take the size as a template parameter, which reaches the
// ABI as a constant and so selects its one-instruction immediate form.
//
// Callable from code shared with the host build: outside ZisK the same names
// forward to the standard functions, so a call site does not need an #if.

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

#include "zkvm_mem.h"

namespace zeg::zisk {

inline void zisk_memcpy(void* dst, const void* src, size_t size) { zkvm_memcpy(dst, src, size); }
template <size_t Size>
inline void zisk_xmemcpy(void* dst, const void* src) { zkvm_memcpy(dst, src, Size); }

inline int64_t zisk_memcmp(const void* a, const void* b, size_t size) { return zkvm_memcmp(a, b, size); }
template <size_t Size>
inline int64_t zisk_xmemcmp(const void* a, const void* b) { return zkvm_memcmp(a, b, Size); }

template <size_t Size, uint8_t Fill = 0>
inline void zisk_xmemset(void* dst) { zkvm_memset(dst, Fill, Size); }
template <uint8_t Fill = 0>
inline void zisk_xmemset(void* dst, size_t size) { zkvm_memset(dst, Fill, size); }

}  // namespace zeg::zisk

#endif  // ZEG_ZISK

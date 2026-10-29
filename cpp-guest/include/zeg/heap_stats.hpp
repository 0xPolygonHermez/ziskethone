#pragma once

// Opt-in heap usage report for the ZisK guest (-DZEG_HEAP_STATS=ON in
// zisk/CMakeLists.txt). heap_mark("phase") prints one UART line:
//   HEAP <phase> used=<main heap bytes> tx_peak=<tx arena peak bytes> free=<bytes>
// tx_peak is the deepest the tx arena has grown so far (zeg/tx_arena.hpp).
// Compiles to nothing otherwise, and on the host.

#if defined(ZEG_ZISK) && defined(ZEG_HEAP_STATS)
#include <cstddef>

#include "zeg/zisk_io.hpp"

extern "C" void zeg_heap_stats(std::size_t* used, std::size_t* tx_peak,
                               std::size_t* free_bytes) noexcept;  // zisk/runtime.cpp
#endif

namespace zeg {

#if defined(ZEG_ZISK) && defined(ZEG_HEAP_STATS)
namespace heap_stats_detail {
inline void put_dec(std::size_t v) {
    char buf[24];
    int n = 0;
    do { buf[n++] = static_cast<char>('0' + v % 10); v /= 10; } while (v != 0);
    while (n > 0) zeg::zisk::uart_putc(buf[--n]);
}
}  // namespace heap_stats_detail

inline void heap_mark(const char* phase) {
    std::size_t used = 0, tx_peak = 0, free_bytes = 0;
    zeg_heap_stats(&used, &tx_peak, &free_bytes);
    zeg::zisk::uart_puts("HEAP ");
    zeg::zisk::uart_puts(phase);
    zeg::zisk::uart_puts(" used=");
    heap_stats_detail::put_dec(used);
    zeg::zisk::uart_puts(" tx_peak=");
    heap_stats_detail::put_dec(tx_peak);
    zeg::zisk::uart_puts(" free=");
    heap_stats_detail::put_dec(free_bytes);
    zeg::zisk::uart_putc('\n');
}
#else
inline void heap_mark(const char*) noexcept {}
#endif

}  // namespace zeg

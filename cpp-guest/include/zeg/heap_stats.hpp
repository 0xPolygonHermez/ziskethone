#pragma once

// Opt-in heap usage report for the ZisK guest (-DZEG_HEAP_STATS=ON in
// zisk/CMakeLists.txt). heap_mark("phase") prints one UART line:
//   HEAP <phase> used=<main heap bytes> tx_peak=<tx arena peak bytes> free=<bytes>
// tx_peak is the deepest the tx arena has grown so far (zeg/tx_arena.hpp).
// heap_block() prints the resources the block spent, which scripts/heap_gate.py
// checks the marks against (HEAP_BUDGET.md):
//   HEAP block fork=<id> txs=<n> withdrawals=<n> input=<bytes> gas_used=<n> regular=<n> state=<n>
// Both compile to nothing otherwise, and on the host.

#include <cstddef>
#include <cstdint>

#if defined(ZEG_ZISK) && defined(ZEG_HEAP_STATS)
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

inline void heap_block(unsigned fork, std::size_t txs, std::size_t withdrawals,
                       std::size_t input_bytes, uint64_t gas_used, uint64_t regular_gas,
                       uint64_t state_gas) {
    const auto field = [](const char* name, std::size_t v) {
        zeg::zisk::uart_puts(name);
        heap_stats_detail::put_dec(v);
    };
    field("HEAP block fork=", fork);
    field(" txs=", txs);
    field(" withdrawals=", withdrawals);
    field(" input=", input_bytes);
    field(" gas_used=", gas_used);
    field(" regular=", regular_gas);
    field(" state=", state_gas);
    zeg::zisk::uart_putc('\n');
}
#else
inline void heap_mark(const char*) noexcept {}
inline void heap_block(unsigned, std::size_t, std::size_t, std::size_t, uint64_t, uint64_t,
                       uint64_t) noexcept {}
#endif

}  // namespace zeg

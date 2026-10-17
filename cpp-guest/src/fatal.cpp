#include "zeg/fatal.hpp"

#include <cstdlib>
#if !defined(ZEG_ZISK)
#include <cstdio>
#else
#include "zeg/zisk_io.hpp"
#endif

namespace zeg {

[[noreturn]] void fatal(const char* msg) {
#if !defined(ZEG_ZISK)
    std::fprintf(stderr, "guest: %s\n", msg);
#else
    // ZisK: same line over the UART. Without it an abort is indistinguishable
    // from a hang or a silent early exit — nothing else reaches the console, and
    // the public output is never written on this path. Only runs on the failure
    // path, so it costs the happy path nothing.
    zeg::zisk::uart_puts("guest: ");
    zeg::zisk::uart_puts(msg);
    zeg::zisk::uart_putc('\n');
#endif
    std::abort();
}

} // namespace zeg

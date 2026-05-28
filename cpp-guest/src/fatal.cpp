#include "zeg/fatal.hpp"

#ifndef ZISK
#include <cstdio>
#include <cstdlib>

namespace zeg {

[[noreturn]] void fatal(const char* msg) {
    std::fprintf(stderr, "guest: %s\n", msg);
    std::abort();
}

} // namespace zeg

#else  // ZISK
// Bare-metal Zisk: write the message to the UART and halt the machine
// via the emulator/prover fail address. No stdio, no abort().

namespace zeg {

[[noreturn]] void fatal(const char* msg) {
    volatile unsigned char* uart = (volatile unsigned char*)0xA0000200;
    const char prefix[] = "guest: ";
    for (const char* p = prefix; *p; ++p) *uart = (unsigned char)*p;
    if (msg) {
        for (const char* p = msg; *p; ++p) *uart = (unsigned char)*p;
    }
    *uart = (unsigned char)'\n';
    // Halt loudly. We deliberately do NOT write the QEMU fail sentinel at
    // 0x100000 — ziskemu's address map rejects that store. Spin forever so
    // the run terminates (the emulator stops at max-steps); the UART line
    // above already surfaced the failure reason.
    for (;;) {}
}

} // namespace zeg

#endif  // ZISK

// Fatal-error helper shared across the guest. Any module that detects an
// unrecoverable condition (state-root mismatch, malformed input, etc.)
// should call `zeg::fatal(msg)` rather than aborting directly, so the
// failure path stays uniform and easy to audit.

#pragma once

namespace zeg {

[[noreturn]] void fatal(const char* msg);

} // namespace zeg

// Debug print shim. On the host build it forwards to fprintf(stderr, ...);
// on the bare-metal Zisk target it compiles to nothing so no newlib stdio
// is pulled in. Use ZEG_DEBUG_PRINTF(fmt, ...) in place of
// std::fprintf(stderr, fmt, ...) for diagnostic-only output.
#ifndef ZISK
#include <cstdio>
#define ZEG_DEBUG_PRINTF(...) std::fprintf(stderr, __VA_ARGS__)
#else
#define ZEG_DEBUG_PRINTF(...) ((void)0)
#endif

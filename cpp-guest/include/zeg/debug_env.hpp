// Debug switches read from the environment (ZEG_STAGE, ZEG_DUMP_*,
// ZEG_TRACE_*): host builds only.
//
// The ZisK ELF has no environment; its libc getenv stub returns null, so the
// switches never fired there, but that rested on which stub got linked, and
// ZEG_STAGE can skip block execution entirely. Under ZEG_ZISK debug_env is a
// constant null, so the compiler drops every hook and its code from the ELF
// (audit 2026-11-17, X-2).

#pragma once

#if !defined(ZEG_ZISK)
#include <cstdlib>
#endif

namespace zeg {

inline const char* debug_env([[maybe_unused]] const char* name) noexcept {
#if defined(ZEG_ZISK)
    return nullptr;
#else
    return std::getenv(name);
#endif
}

}  // namespace zeg

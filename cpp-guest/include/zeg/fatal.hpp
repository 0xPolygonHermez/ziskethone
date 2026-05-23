// Fatal-error helper shared across the guest. Any module that detects an
// unrecoverable condition (state-root mismatch, malformed input, etc.)
// should call `zeg::fatal(msg)` rather than aborting directly, so the
// failure path stays uniform and easy to audit.

#pragma once

namespace zeg {

[[noreturn]] void fatal(const char* msg);

} // namespace zeg

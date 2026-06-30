// In-memory stateless block-validation entry point.
//
// `run` runs the same pipeline as the guest's `main()` (parse
// the input collections, verify the pre-execution state root, execute the
// block, recompute the post-execution state root, build the header, and
// compute the execution-layer block hash) but operates on an in-memory ZEG0
// container instead of reading from a file or the ZisK MMIO input region.
//
// It is the shared core used both by `main()` and by the C FFI wrapper
// (`zeg_run`) so the host can run the EVM in-process.

#pragma once

#include <cstddef>
#include <cstdint>

namespace zeg {

// Returned by `run` when the `ZEG_STAGE` debug selector requested a partial
// run: the pipeline stopped before computing the block hash, so `out` was NOT
// written and the caller must not read it. A normal (non-debug) run never
// returns this. Distinct from 0 so the FFI caller can detect "no hash
// produced" instead of silently consuming an uninitialized buffer.
constexpr int kRunNoHashPartialStage = 2;

// Runs the full stateless block validation on an in-memory ZEG0 container.
// `input`/`len` is the container bytes (starting with the ZEG0 magic).
// On success writes the 32-byte execution block hash to out[32] and returns 0.
// Returns `kRunNoHashPartialStage` (nonzero, `out` untouched) only when the
// ZEG_STAGE debug selector requested a partial run. Bad witnesses fatal via
// zeg::fatal rather than returning.
int run(const uint8_t* input, size_t len, uint8_t out[32]);

} // namespace zeg

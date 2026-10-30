// evmc2.h — an analysis-aware, backwards-compatible extension of the evmc API.
//
// The plain evmc ABI has no notion of "pre-analyzed code": its `execute` takes
// raw bytecode and the VM must (re)analyze it on every call. evmone's baseline
// interpreter rebuilds a full CodeAnalysis (jumpdest map + padded code) per call,
// which dominates cost when a contract is invoked many times in a block. Caching
// that analysis requires reaching into evmone internals, which couples the host
// to a specific VM and breaks the evmc drop-in boundary.
//
// evmc2 adds analysis caching as a first-class concept via three functions —
// `prepare`, `execute2`, `release_pre_execution` — while staying a strict
// superset of evmc: `evmc2_vm` begins with an `evmc_vm`, so an `evmc2_vm*` is
// usable anywhere an `evmc_vm*` is expected. evmc-only clients ignore the extra
// fields; evmc2-aware clients analyze once and reuse the result across calls.
//
// Any VM backend that implements this interface (the evmone adapter today, a
// hand-written EVM tomorrow) plugs into an evmc2-aware host with no special
// casing.

#ifndef EVMC2_H
#define EVMC2_H

#include <evmc/evmc.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque, EVM-internal handle to a prepared (analyzed) piece of code. Only the
// VM that produced it knows the concrete layout — exactly like
// `evmc_host_context`. Created by `prepare`, consumed by `execute2`, freed by
// `release_pre_execution`.
typedef struct evmc2_pre_execution evmc2_pre_execution;

// Analyze `code` once and return a reusable handle.
//
// If `out_buf` is non-NULL, the backend MUST lay the entire analysis inside
// `out_buf` (capacity `out_cap` bytes, guaranteed >= the backend's maximum
// analysis size) and return a handle pointing within it; such a handle is
// owned by the caller's arena and `release_pre_execution` on it is a no-op.
// If `out_buf` is NULL the handle is heap-allocated and must be freed with
// `release_pre_execution` (the legacy path, used on the host and for code that
// is not cached). The analysis-cache (zeg/analysis_cache.hpp) always passes a
// slot buffer so the guest never grows the heap per distinct contract.
typedef evmc2_pre_execution* (*evmc2_prepare_fn)(struct evmc_vm* vm,
                                                 uint8_t const* code,
                                                 size_t code_size,
                                                 uint8_t* out_buf,
                                                 size_t out_cap);

// Free a handle previously returned by `prepare`.
typedef void (*evmc2_release_pre_execution_fn)(struct evmc_vm* vm,
                                               evmc2_pre_execution* pre);

// Identical to `evmc_execute_fn` plus a trailing `pre` argument:
//   * pre != NULL — execute using the prepared analysis, skipping re-analysis
//                   (`code`/`code_size` must describe the same code `pre` was
//                   prepared from);
//   * pre == NULL — behave exactly like `execute` (analyze `code` fresh).
typedef struct evmc_result (*evmc2_execute2_fn)(
    struct evmc_vm* vm,
    const struct evmc_host_interface* host,
    struct evmc_host_context* context,
    enum evmc_revision rev,
    const struct evmc_message* msg,
    uint8_t const* code,
    size_t code_size,
    evmc2_pre_execution* pre);

// The extended VM handle. `base` is the first member, so:
//   (struct evmc_vm*)v == &v->base
// and an `evmc2_vm*` can be passed to any evmc API. `base.execute` etc. keep
// working for evmc-only consumers; evmc2-aware consumers additionally use the
// three function pointers below.
struct evmc2_vm
{
    struct evmc_vm                 base;
    evmc2_prepare_fn               prepare;
    evmc2_execute2_fn              execute2;
    evmc2_release_pre_execution_fn release_pre_execution;
    // Max bytes a single `prepare` needs when writing into a caller slot
    // (sized for this backend at the largest possible code size). The analysis
    // cache uses it as its fixed slot size. 0 if the backend has no slot path.
    size_t                         analysis_slot_bytes;
    // Drops the VM's per-transaction buffers (EVM memory, return data). The
    // host calls it at each transaction and system-call start, before the
    // guest's per-transaction arena is reset. NULL if the backend keeps none.
    void (*release_tx_buffers)(struct evmc_vm* vm);
};

#ifdef __cplusplus
}
#endif

#endif  // EVMC2_H

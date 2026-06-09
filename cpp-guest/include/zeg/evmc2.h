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

// Analyze `code` once and return a reusable handle. The handle is owned by the
// caller and must be freed with the matching `release_pre_execution`.
typedef evmc2_pre_execution* (*evmc2_prepare_fn)(struct evmc_vm* vm,
                                                 uint8_t const* code,
                                                 size_t code_size);

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
};

#ifdef __cplusplus
}
#endif

#endif  // EVMC2_H

// evmc2_evmone.hpp — factory for an evmc2 VM backed by evmone's baseline.
//
// This is the single place that depends on evmone internals (baseline analyze /
// the pre-analyzed execute overload). Everything else in the guest talks to the
// VM through the backend-agnostic evmc2 interface.

#pragma once

#include "zeg/evmc2.h"

#ifdef __cplusplus
extern "C" {
#endif

// Create an evmc2 VM that runs evmone's baseline interpreter. It owns an
// underlying `evmc_create_evmone()` instance; free it via `base.destroy`. Never
// returns NULL.
evmc2_vm* evmc2_create_evmone(void);

#ifdef __cplusplus
}
#endif

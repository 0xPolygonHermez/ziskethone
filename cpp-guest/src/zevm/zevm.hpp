// zevm.hpp — public evmc2 factory for the hand-written EVM.
//
// zevm is a drop-in replacement for evmone at the evmc2 boundary. A client
// obtains an instance with evmc2_create_zevm() exactly as it would with
// evmc2_create_evmone(), then drives it through prepare / execute2 / the base
// evmc operations.

#pragma once

#include "zeg/evmc2.h"

#if __cplusplus
extern "C" {
#endif

// Creates a zevm instance as an evmc2 VM. Mirrors evmc2_create_evmone(). Never
// returns NULL.
evmc2_vm* evmc2_create_zevm(void);

#if __cplusplus
}
#endif

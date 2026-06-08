// zevm.hpp — public evmc factory for the hand-written EVM.
//
// zevm is a drop-in replacement for evmone at the evmc C-ABI boundary. A client
// obtains a VM instance with evmc_create_zevm() exactly as it would with
// evmc_create_evmone(), then drives it through the returned evmc_vm's function
// pointers (execute / get_capabilities / destroy).

#pragma once

#include <evmc/evmc.h>
#include <evmc/utils.h>  // EVMC_EXPORT / EVMC_NOEXCEPT

#if __cplusplus
extern "C" {
#endif

// Creates a zevm instance. Mirrors evmc_create_evmone(). Never returns NULL.
EVMC_EXPORT struct evmc_vm* evmc_create_zevm(void) EVMC_NOEXCEPT;

#if __cplusplus
}
#endif

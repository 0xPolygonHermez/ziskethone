// modexp_zisk.cpp — MODEXP precompile (0x05, EIP-198/2565) for the ZisK build,
// through the EF zkVM accelerator ABI. Provides the symbol evmone's expmod
// precompile calls:
//
//   evmone::crypto::modexp(base, exp, mod, output)
//
// as one zkvm_modexp call. Both sides use the EVM big-endian byte encoding, so
// there is no marshalling.

#include <cstddef>
#include <cstdint>
#include <span>

#include <evmone_precompiles/modexp.hpp>  // declaration
#include "zkvm_accelerators.h"
#include "zeg/fatal.hpp"

namespace evmone::crypto {

void modexp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
            std::span<const uint8_t> mod, uint8_t* output) noexcept {
    // Abort on any non-OK accelerator status rather than proceed with an
    // undefined `output`. Unreachable today (evmone validates the inputs first);
    // a guard against future zisklib changes.
    if (zkvm_modexp(base.data(), base.size(), exp.data(), exp.size(),
                    mod.data(), mod.size(), output) != ZKVM_EOK) {
        zeg::fatal("zkvm_modexp failed");
    }
}

}  // namespace evmone::crypto

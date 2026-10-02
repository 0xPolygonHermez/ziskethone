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

namespace evmone::crypto {

void modexp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
            std::span<const uint8_t> mod, uint8_t* output) noexcept {
    zkvm_modexp(base.data(), base.size(), exp.data(), exp.size(),
                mod.data(), mod.size(), output);
}

}  // namespace evmone::crypto

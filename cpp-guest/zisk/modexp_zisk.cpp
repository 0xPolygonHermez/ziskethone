// modexp_zisk.cpp — MODEXP precompile (0x05, EIP-198/2565) for the ZisK build.
// Provides the symbol evmone's expmod precompile calls:
//
//   evmone::crypto::modexp(base, exp, mod, output)
//
// delegating to the self-contained arbitrary-precision modexp in bigint/, which
// runs on the ZisK arith256/add256 precompiles + bin_decomp/bigint_div fcall
// hints. Replaces the failure stub in precompile_stubs.cpp.

#include <cstddef>
#include <cstdint>
#include <span>

#include <evmone_precompiles/modexp.hpp>  // declaration

#include "bigint/modexp.hpp"
#ifdef ZKVM_MODEXP
#include "zkvm_accelerators.h"
#endif

namespace evmone::crypto {

void modexp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
            std::span<const uint8_t> mod, uint8_t* output) noexcept {
#ifdef ZKVM_MODEXP
    // EF standard C ABI: redirected by elf2rom to the native .zisk modexp. Both
    // sides use the EVM big-endian byte encoding, so no marshalling is needed.
    zkvm_modexp(base.data(), base.size(), exp.data(), exp.size(),
                mod.data(), mod.size(), output);
#else
    zeg::bi::modexp_compute(base.data(), (int)base.size(), exp.data(), (int)exp.size(),
                            mod.data(), (int)mod.size(), output);
#endif
}

}  // namespace evmone::crypto

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

namespace evmone::crypto {

void modexp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
            std::span<const uint8_t> mod, uint8_t* output) noexcept {
    zeg::bi::modexp_compute(base.data(), (int)base.size(), exp.data(), (int)exp.size(),
                            mod.data(), (int)mod.size(), output);
}

}  // namespace evmone::crypto

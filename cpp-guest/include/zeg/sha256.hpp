// Thin wrapper around evmone's sha256 that returns an evmc::bytes32
// (the type the rest of the guest passes around). Header-only so
// callers can just include it without pulling in evmone_precompiles
// transitively. Mirrors the style of zeg/keccak.hpp.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/sha256.hpp>

namespace zeg {

inline evmc::bytes32 sha256_bytes32(const uint8_t* data, std::size_t size) {
    evmc::bytes32 h;
    evmone::crypto::sha256(reinterpret_cast<std::byte*>(h.bytes),
                           reinterpret_cast<const std::byte*>(data),
                           size);
    return h;
}

} // namespace zeg

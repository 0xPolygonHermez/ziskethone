// Thin wrapper around evmone's keccak256 that returns an evmc::bytes32
// (the type the rest of the guest passes around). Header-only so the
// few callers (state_root.cpp, blocks.cpp, …) can just include it
// without pulling in evmone_precompiles transitively.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/keccak.hpp>

namespace zeg {

inline evmc::bytes32 keccak256_bytes32(const uint8_t* data, std::size_t size) {
    const auto digest = ethash::keccak256(data, size);
    evmc::bytes32 h;
    std::memcpy(h.bytes, digest.bytes, sizeof(h.bytes));
    return h;
}

} // namespace zeg

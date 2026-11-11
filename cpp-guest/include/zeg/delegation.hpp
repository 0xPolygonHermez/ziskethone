// EIP-7702 delegation designator: exactly `0xef0100 || address`, 23 bytes.
//
// Code with the same prefix and any other length is ordinary code, which
// aborts on the 0xef opcode (EIP-7702; Geth, revm and execution-specs agree).
// EIP-3541 stops new 0xef code after London, so such code can only be pre-London
// mainnet code, but a prefix-only check would still run it as a delegation
// (audit S1). Every guest site that routes or charges a delegation uses this.

#pragma once

#include <cstddef>
#include <cstdint>

namespace zeg {

inline constexpr std::size_t kDelegationDesignatorSize = 23;

inline bool is_delegation_designator(const uint8_t* code, std::size_t size) noexcept {
    return size == kDelegationDesignatorSize &&
           code[0] == 0xef && code[1] == 0x01 && code[2] == 0x00;
}

} // namespace zeg

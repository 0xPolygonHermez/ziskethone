#include "zeg/bloom.hpp"

#include <evmc/evmc.hpp>

#include "zeg/keccak.hpp"

namespace zeg {

void bloom_add(std::array<uint8_t, 256>& bloom,
               const uint8_t* data, std::size_t size) {
    const evmc::bytes32 h = keccak256_bytes32(data, size);
    for (int i = 0; i < 3; ++i) {
        const uint16_t pair     =
            (uint16_t(h.bytes[i * 2]) << 8) | h.bytes[i * 2 + 1];
        const uint16_t p        = pair & 0x07FF;            // [0, 2047]
        const std::size_t byte_idx = 256 - 1 - (p >> 3);
        const uint8_t  bit_mask = uint8_t(1) << (p & 0x07);
        bloom[byte_idx] |= bit_mask;
    }
}

void bloom_or_into(std::array<uint8_t, 256>&       dst,
                   const std::array<uint8_t, 256>& src) {
    for (std::size_t i = 0; i < 256; ++i) {
        dst[i] |= src[i];
    }
}

} // namespace zeg

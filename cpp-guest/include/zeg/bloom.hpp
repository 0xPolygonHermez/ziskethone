// 2048-bit logs bloom filter (Yellow Paper §4.4.2). Two operations:
//
//   bloom_add(bloom, data, size) — set 3 bits derived from keccak256(data).
//   bloom_or_into(dst, src)      — OR 256 source bytes into 256 dst bytes.
//
// The Yellow Paper bloom takes 11-bit indices from byte-pairs of
// keccak256(data) and sets the corresponding bits in a big-endian
// packed 256-byte buffer. `bloom_add` is used per log topic / address;
// `bloom_or_into` aggregates a tx's receipt bloom into the block bloom.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace zeg {

void bloom_add(std::array<uint8_t, 256>& bloom,
               const uint8_t* data, std::size_t size);

void bloom_or_into(std::array<uint8_t, 256>&       dst,
                   const std::array<uint8_t, 256>& src);

} // namespace zeg

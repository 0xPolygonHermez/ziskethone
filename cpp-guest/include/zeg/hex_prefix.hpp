// Hex-prefix (HP) encoder for Ethereum Merkle Patricia Trie paths.
//
// HP packs a nibble sequence into bytes (two nibbles per byte) and tags
// the first byte with two bits:
//   bit 5 = leaf flag       (1 = leaf node, 0 = extension node)
//   bit 4 = odd-length flag (1 = odd nibble count, 0 = even)
//
// When odd-length is set, the low nibble of the first byte carries the
// first input nibble. Subsequent bytes pack the remaining nibbles in
// pairs (high nibble first).

#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace zeg {

// Hex-prefix encode `nibbles` (one nibble per byte, low 4 bits used).
// `leaf` selects the leaf vs. extension flag. Output size is
// `ceil((nibbles.size() + 1) / 2)`.
std::vector<uint8_t> hex_prefix(std::span<const uint8_t> nibbles, bool leaf);

} // namespace zeg

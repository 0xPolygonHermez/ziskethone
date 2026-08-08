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

#include "zeg/trie_node.hpp"

namespace zeg {

// A trie path is at most 64 nibbles (a 32-byte key hash), so an HP encoding is
// at most 33 bytes — small enough to return by value, which keeps the trie
// builder from paying a heap allocation per node just to hold it. data()/size()
// plus begin()/end() make it usable anywhere the old std::vector return was,
// including as a contiguous range for `BytesView{...}`.
struct HpBytes {
    static constexpr std::size_t kMaxNibbles = 64;

    uint8_t buf[kMaxNibbles / 2 + 1];
    uint8_t len = 0;

    const uint8_t* data()  const noexcept { return buf; }
    std::size_t    size()  const noexcept { return len; }
    const uint8_t* begin() const noexcept { return buf; }
    const uint8_t* end()   const noexcept { return buf + len; }
};

// Hex-prefix encode `path`. `leaf` selects the leaf vs. extension flag. Output
// size is `ceil((path.size() + 1) / 2)`. Aborts via zeg::fatal if the path is
// longer than `HpBytes::kMaxNibbles`.
//
// When the path's packing already has the parity HP wants — which it does for
// every path derived from a key, see PackedPath — the body is a copy of the
// packed bytes. Otherwise it falls back to shifting nibble by nibble, which is
// what this function did for every path when paths were stored unpacked.
HpBytes hex_prefix(const PackedPath& path, bool leaf);

// Same encoding from one nibble per byte, for the transaction and receipt
// tries: their keys are RLP-encoded indices, so the paths are a handful of
// nibbles and never worth packing.
HpBytes hex_prefix(std::span<const uint8_t> nibbles, bool leaf);

} // namespace zeg

// Minimal RLP (Recursive Length Prefix) encoder for the ZisK guest.
//
// We only need encoding (the guest never has to decode RLP from untrusted
// input — the trie node hashes happen on data we constructed). The four
// public entry points cover everything the state-root walker needs:
//
//   encode(BytesView)          - byte string
//   encode_u64(uint64_t)       - integer string (big-endian, trimmed)
//   encode_u256(uint256be)     - integer string (big-endian, trimmed)
//   encode_list(items)         - wrap N already-RLP-encoded items as a list

#pragma once

#include <cstdint>
#include <initializer_list>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg::rlp {

using Bytes     = std::vector<uint8_t>;
using BytesView = std::span<const uint8_t>;

// Encode a byte string. A single byte < 0x80 encodes as itself; longer
// strings get a 1-byte short header (≤ 55 B) or a multi-byte long header.
Bytes encode(BytesView data);

// Encode a uint64 as an RLP string (big-endian, leading-zero trimmed —
// so 0 encodes as the empty string 0x80, 1 as the single byte 0x01, etc.).
Bytes encode_u64(uint64_t v);

// Encode an evmc::uint256be (32-byte big-endian) as an RLP string with
// leading zeros trimmed.
Bytes encode_u256(const evmc::uint256be& v);

// Wrap N already-RLP-encoded items into an RLP list. Caller supplies the
// items already encoded (because each item is typically encoded with the
// matching `encode*` overload — the list helper only handles the wrapper).
Bytes encode_list(std::initializer_list<BytesView> items);

} // namespace zeg::rlp

// SSZ Merkleization (hash_tree_root) helpers — just enough to compute the
// EIP-8025 `new_payload_request_root` (see zeg/new_payload_request.hpp).
//
// Covers the classic SSZ merkleize / mix_in_length plus the progressive
// variants of EIP-7916 (ProgressiveList, `merkleize_progressive`) and
// EIP-7495 (ProgressiveContainer, `mix_in_active_fields`). Only roots are
// computed; nothing here serializes SSZ. The hash is SHA-256 (the ZisK
// precompile on the guest, evmone's portable one on the host).

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include <evmc/evmc.hpp>

namespace zeg::ssz {

using Chunk = evmc::bytes32;

// sha256(a || b).
Chunk hash(const Chunk& a, const Chunk& b) noexcept;

// Root of the depth-d all-zero subtree (zero_hash(0) is the zero chunk).
const Chunk& zero_hash(unsigned depth) noexcept;

// merkleize(chunks, limit): binary tree over `chunks` padded with zero
// chunks to next_pow2(limit) leaves. `chunks.size()` must be <= `limit`.
Chunk merkleize(std::span<const Chunk> chunks, uint64_t limit) noexcept;

// EIP-7916 merkleize_progressive(chunks, 1): a 0-terminated chain of binary
// subtrees with 1, 4, 16, ... leaves.
Chunk merkleize_progressive(std::span<const Chunk> chunks) noexcept;

// hash(root, uint256(length)).
Chunk mix_in_length(const Chunk& root, uint64_t length) noexcept;

// EIP-7495 hash(root, pack_bits(active_fields)) for an all-ones
// active_fields of `n_active` (<= 256) entries.
Chunk mix_in_active_fields(const Chunk& root, unsigned n_active) noexcept;

// ----- basic-type roots -----
Chunk uint64_root(uint64_t v) noexcept;
// uint256 from a big-endian word (SSZ packs it little-endian).
Chunk uint256_root(const evmc::uint256be& v) noexcept;

// ----- byte sequences -----
// ByteVector[N] (N = bytes.size()).
Chunk byte_vector_root(std::span<const uint8_t> bytes) noexcept;
// ByteList[max_bytes].
Chunk byte_list_root(std::span<const uint8_t> bytes, uint64_t max_bytes) noexcept;
// ProgressiveByteList.
Chunk progressive_byte_list_root(std::span<const uint8_t> bytes) noexcept;

}  // namespace zeg::ssz

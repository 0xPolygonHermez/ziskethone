// Shared MPT node-result types for the ZisK state-root reconstruction.
//
// `NodeR` is the computed result of one trie node (a hash for multi-child
// branches / leaves, or a folded `{nibbles, child}` for single-child
// chains). It used to be nested in `StateRoot`; it lives here so the
// Accounts / Storages tables can cache their own leaf result (and an
// account's storage-subtree link) on each row.
//
// The explicit node array (`BranchNode` + typed `Child`) lets the
// new-root pass walk the materialized tree instead of re-parsing the
// stream. `Child::idx` resolves by `Child::type`:
//   * Branch                       -> StateRoot::branch_nodes_
//   * Account / Storage            -> the Accounts / Storages row (the row
//                                     owns its cached `NodeR`)
//   * Hash / ExtensionHash /
//     PhantomLeaf                  -> StateRoot::aux_ (a fixed, always
//                                     read-only `NodeR`, built once)
//   * Empty                        -> unused (a static EmptyR result)

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <variant>
#include <vector>

#include <evmc/evmc.hpp>

#include "zeg/fatal.hpp"

namespace zeg {

// ----- node-result variant --------------------------------------------------

struct EmptyR {};
struct HashR  { evmc::bytes32 hash; };
struct ExtR   {
    std::vector<uint8_t> ext_nibbles;  // one nibble per byte
    evmc::bytes32        hash;
};
struct AccountLeafR {
    std::vector<uint8_t> path_nibbles;
    std::size_t          account_idx;
    evmc::bytes32        storage_root;
};
struct StorageLeafR {
    std::vector<uint8_t> path_nibbles;
    std::size_t          storage_idx;
};
/// Keyless sibling leaf carried inline via `Op::PhantomLeaf` (Reth omitted
/// its keccak preimage). `value_rlp` is the leaf's raw inner value bytes;
/// it is wrapped in HP + RLP at pack time.
struct PhantomLeafR {
    std::vector<uint8_t> path_nibbles;
    std::vector<uint8_t> value_rlp;
};

using NodeR = std::variant<EmptyR, HashR, ExtR, AccountLeafR, StorageLeafR, PhantomLeafR>;

// Construct a NodeR holding alternative `T`. Default-construct then
// `.emplace<T>(...)` rather than the converting / in_place_type ctors —
// VS Code's IntelliSense parser (a Microsoft EDG fork) rejects those for
// this variant even though every real compiler accepts them.
template <typename T, typename... Args>
inline NodeR mk_node(Args&&... args) {
    NodeR n;
    n.template emplace<T>(std::forward<Args>(args)...);
    return n;
}

// ----- explicit node array --------------------------------------------------

enum class NodeType : uint8_t {
    Empty,
    Branch,
    Account,
    Storage,
    Hash,
    ExtensionHash,
    PhantomLeaf,
};

struct Child {
    NodeType type = NodeType::Empty;
    uint32_t idx  = 0;
};

struct BranchNode {
    std::array<Child, 16> children;
    NodeR                 cached;  // computed result of this branch (post-fold)
};

// ----- shared constants + emptiness predicates ------------------------------

// keccak256(rlp("")) — empty-trie root.
inline constexpr evmc::bytes32 kEmptyTrieRoot{{
    0x56,0xe8,0x1f,0x17,0x1b,0xcc,0x55,0xa6,
    0xff,0x83,0x45,0xe6,0x92,0xc0,0xf8,0x6e,
    0x5b,0x48,0xe0,0x1b,0x99,0x6c,0xad,0xc0,
    0x01,0x62,0x2f,0xb5,0xe3,0x63,0xb4,0x21,
}};

// keccak256("") — code hash of an account with no code.
inline constexpr evmc::bytes32 kEmptyCodeHash{{
    0xc5,0xd2,0x46,0x01,0x86,0xf7,0x23,0x3c,
    0x92,0x7e,0x7d,0xb2,0xdc,0xc7,0x03,0xc0,
    0xe5,0x00,0xb6,0x53,0xca,0x82,0x27,0x3b,
    0x7b,0xfa,0xd8,0x04,0x5d,0x85,0xa4,0x70,
}};

inline bool is_empty_account(uint64_t nonce,
                             const evmc::uint256be& balance,
                             const evmc::bytes32& code_hash) {
    if (nonce != 0) return false;
    static constexpr evmc::uint256be kZeroBalance{};
    if (std::memcmp(&balance, &kZeroBalance, sizeof(balance)) != 0) return false;
    if (std::memcmp(&code_hash, &kEmptyCodeHash, sizeof(code_hash)) != 0) return false;
    return true;
}

inline bool is_zero_value(const evmc::bytes32& v) {
    static constexpr evmc::bytes32 kZero{};
    return std::memcmp(&v, &kZero, sizeof(v)) == 0;
}

// The `i`-th nibble of a 32-byte hash (high nibble of byte i/2 first).
inline uint8_t nibble_at(const evmc::bytes32& key_hash, std::size_t i) {
    const uint8_t b = key_hash.bytes[i / 2];
    return static_cast<uint8_t>((i % 2 == 0) ? (b >> 4) : (b & 0x0f));
}

// Build the leaf path: the remaining nibbles of `key_hash` from `depth`.
// A trie path is at most 64 nibbles, so it is expanded into an inline buffer
// (same reasoning as HpBytes) rather than a heap vector: this runs once per leaf
// in both trie passes, and the result is copied into the node's own storage
// immediately afterwards.
struct NibblePath {
    static constexpr std::size_t kMax = 64;

    uint8_t buf[kMax];
    uint8_t len = 0;

    const uint8_t* data()  const noexcept { return buf; }
    std::size_t    size()  const noexcept { return len; }
    const uint8_t* begin() const noexcept { return buf; }
    const uint8_t* end()   const noexcept { return buf + len; }
};

inline NibblePath nibbles_from(const evmc::bytes32& key_hash, std::size_t depth) {
    // Not a caller precondition: `64 - depth` would wrap and leave `len` past
    // the buffer, and the walk that bounds `depth` is in another file.
    if (depth > NibblePath::kMax) {
        fatal("nibbles_from: trie depth beyond the 64-nibble key");
    }

    NibblePath out;
    out.len = static_cast<uint8_t>(NibblePath::kMax - depth);

    uint8_t* p = out.buf;
    std::size_t i = depth;
    if (i & 1) {  // an odd depth starts mid-byte
        *p++ = static_cast<uint8_t>(key_hash.bytes[i >> 1] & 0x0f);
        ++i;
    }
    for (; i < NibblePath::kMax; i += 2) {  // then two nibbles per byte
        const uint8_t b = key_hash.bytes[i >> 1];
        p[0] = static_cast<uint8_t>(b >> 4);
        p[1] = static_cast<uint8_t>(b & 0x0f);
        p += 2;
    }
    return out;
}

} // namespace zeg

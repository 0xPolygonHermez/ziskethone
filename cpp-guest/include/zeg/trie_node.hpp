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

// A trie path stored the way the encoder consumes it: packed two nibbles per
// byte, plus which half of the first byte the path starts at.
//
// The one-nibble-per-byte form this replaces existed for a single operation —
// the fold prepends the branch nibble to its only child's path on the way up —
// and that operation costs 0.02% of a block while unpacking and repacking
// around it cost 3.8%. Packed, the prepend is still O(1): with the first nibble
// in the low half there is already room above it, and otherwise the path grows
// one byte towards the front, which is why the bytes sit at the END of the
// buffer and `start` walks backwards.
//
// `off` and the nibble count keep the parity the hex-prefix encoder wants,
// for free: a leaf path is the last 64-depth nibbles of a key, so it starts at
// half `depth % 2` and has `64 - depth` nibbles — same parity, 64 being even —
// and each prepend flips both. When they do match, encoding is a copy; when
// they do not (an extension path read from the witness at an arbitrary length)
// the encoder shifts, which is what the old representation did for every path.
struct PackedPath {
    static constexpr std::size_t kMaxNibbles = 64;
    // 33 bytes is the widest a 64-nibble path can span (an odd start adds one),
    // and the tail never moves, so growing to the front can never reach byte 0.
    static constexpr std::size_t kCap = 34;

    uint8_t buf[kCap];
    uint8_t start = kCap;  // first byte in use
    uint8_t off   = 0;     // 0: first nibble in the high half of buf[start], 1: low
    uint8_t len   = 0;     // nibbles

    std::size_t size()  const noexcept { return len; }
    bool        empty() const noexcept { return len == 0; }
    // Bytes the packed nibbles span, including a half-used first byte.
    std::size_t bytes() const noexcept { return (std::size_t{off} + len + 1) / 2; }
    const uint8_t* data() const noexcept { return buf + start; }
    // True when the packing already has the parity hex_prefix wants.
    bool aligned_for_hp() const noexcept { return off == (len & 1U); }

    uint8_t at(std::size_t i) const noexcept {
        const std::size_t p = std::size_t{off} + i;
        const uint8_t b = buf[start + p / 2];
        return static_cast<uint8_t>((p & 1U) ? (b & 0x0f) : (b >> 4));
    }

    void prepend(uint8_t nib) {
        // Bounding the nibble count is what keeps `start` inside the buffer: at
        // 64 nibbles the path spans at most 33 bytes, so `start` stops at 1.
        if (len >= kMaxNibbles) {
            fatal("PackedPath: prepend past the 64-nibble capacity");
        }
        if (off) {  // room in the high half of the leading byte
            buf[start] = static_cast<uint8_t>((nib << 4) | (buf[start] & 0x0f));
            off = 0;
        } else {    // take one more byte at the front
            --start;
            buf[start] = static_cast<uint8_t>(nib & 0x0f);
            off = 1;
        }
        ++len;
    }

    // Drop the first `k` nibbles — the phantom-leaf shortening in split_leaf.
    void drop_front(std::size_t k) {
        if (k > len) {
            fatal("PackedPath: drop_front past the end of the path");
        }
        const std::size_t p = std::size_t{off} + k;
        start = static_cast<uint8_t>(start + p / 2);
        off   = static_cast<uint8_t>(p & 1U);
        len   = static_cast<uint8_t>(len - k);
    }

    // Anchor `n` nibbles starting at half `first_off` of `src` at the end of the
    // buffer, so every later prepend fits in front.
    void assign(const uint8_t* src, std::size_t first_off, std::size_t n) {
        if (n > kMaxNibbles) {
            fatal("PackedPath: path longer than 64 nibbles");
        }
        const std::size_t nbytes = (first_off + n + 1) / 2;
        start = static_cast<uint8_t>(kCap - nbytes);
        off   = static_cast<uint8_t>(first_off);
        len   = static_cast<uint8_t>(n);
        std::memcpy(buf + start, src, nbytes);
    }
};

struct EmptyR {};
struct HashR  { evmc::bytes32 hash; };
struct ExtR   {
    PackedPath    ext_nibbles;
    evmc::bytes32 hash;
};
struct AccountLeafR {
    PackedPath           path_nibbles;
    std::size_t          account_idx;
    evmc::bytes32        storage_root;
};
struct StorageLeafR {
    PackedPath           path_nibbles;
    std::size_t          storage_idx;
};
/// Keyless sibling leaf carried inline via `Op::PhantomLeaf` (Reth omitted
/// its keccak preimage). `value_rlp` is the leaf's raw inner value bytes;
/// it is wrapped in HP + RLP at pack time.
struct PhantomLeafR {
    PackedPath           path_nibbles;
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

// The leaf path at `depth`: the key's remaining nibbles, packed. No unpacking
// at all — the tail of the key is already the packed form, so this is a copy of
// at most 32 bytes where the nibble-per-byte version wrote 64 bytes one at a
// time. `depth % 2` is where the first nibble sits inside the first byte.
inline PackedPath path_from_key(const evmc::bytes32& key_hash, std::size_t depth) {
    if (depth > PackedPath::kMaxNibbles) {
        fatal("path_from_key: trie depth beyond the 64-nibble key");
    }
    PackedPath out;
    out.assign(key_hash.bytes + depth / 2, depth & 1U,
               PackedPath::kMaxNibbles - depth);
    return out;
}


} // namespace zeg

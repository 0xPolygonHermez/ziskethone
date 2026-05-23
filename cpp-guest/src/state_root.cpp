#include "zeg/state_root.hpp"

#include <array>
#include <cstring>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <evmone_precompiles/keccak.hpp>

#include "zeg/accounts.hpp"
#include "zeg/fatal.hpp"
#include "zeg/hex_prefix.hpp"
#include "zeg/rlp.hpp"
#include "zeg/storages.hpp"
#include "zeg/stream.hpp"

namespace zeg {

namespace {

// Stream-encoded node opcodes (u64 each, 8-byte aligned).
enum class Op : uint64_t {
    Empty         = 0,
    Hash          = 1,
    ExtensionHash = 2,
    Leaf          = 3,
    Node          = 4,
};

enum class TreeKind : uint8_t { State, Storage };

// ----- result of one recursive node evaluation -----
//
// A Node never escapes the recursion: the reduction step always collapses
// 16 children into one of the four other shapes (Empty / Hash / Ext / Leaf).

struct EmptyR {};
struct HashR  { evmc::bytes32 hash; };
struct ExtR   {
    std::vector<uint8_t> ext_nibbles;  // unpacked, one nibble per byte
    evmc::bytes32 hash;
};
struct AccountLeafR {
    std::vector<uint8_t> path_nibbles;
    size_t        account_idx;
    evmc::bytes32 storage_root;  // computed from the embedded storage subtree
};
struct StorageLeafR {
    std::vector<uint8_t> path_nibbles;
    size_t storage_idx;
};

using NodeR = std::variant<EmptyR, HashR, ExtR, AccountLeafR, StorageLeafR>;

// Helper: construct a NodeR holding alternative `T`. We default-construct
// the variant and then `.emplace<T>(...)` rather than relying on variant's
// converting constructor or its `in_place_type` constructor — VS Code's
// IntelliSense parser (a Microsoft EDG fork) does not recognise either
// of those for our variant, even though every real compiler does. The
// emplace member template parses cleanly in IntelliSense too.
template <typename T, typename... Args>
NodeR mk_node(Args&&... args) {
    NodeR n;
    n.template emplace<T>(std::forward<Args>(args)...);
    return n;
}

// keccak256(rlp("")) — empty-trie root. Constant from the yellow paper.
constexpr evmc::bytes32 kEmptyTrieRoot{{
    0x56,0xe8,0x1f,0x17,0x1b,0xcc,0x55,0xa6,
    0xff,0x83,0x45,0xe6,0x92,0xc0,0xf8,0x6e,
    0x5b,0x48,0xe0,0x1b,0x99,0x6c,0xad,0xc0,
    0x01,0x62,0x2f,0xb5,0xe3,0x63,0xb4,0x21,
}};

// ----- helpers -----

evmc::bytes32 keccak_bytes32(const uint8_t* data, size_t size) {
    const auto digest = ethash::keccak256(data, size);
    evmc::bytes32 h;
    std::memcpy(h.bytes, digest.bytes, sizeof(h.bytes));
    return h;
}

// Convert a 32-byte hash to 64 unpacked nibbles starting from offset
// `start_nibble`. Used to build a leaf's remaining-path at its depth.
std::vector<uint8_t> nibbles_from(const evmc::bytes32& hash, size_t start_nibble) {
    std::vector<uint8_t> out;
    out.reserve(64 - start_nibble);
    for (size_t i = start_nibble; i < 64; ++i) {
        const uint8_t b = hash.bytes[i / 2];
        out.push_back(static_cast<uint8_t>((i % 2 == 0) ? (b >> 4) : (b & 0x0f)));
    }
    return out;
}

// ----- pack* (RLP + HP + keccak) -----

// Leaf node = [HP(path, leaf=true), value_bytes]. For the state trie the
// value_bytes is the RLP-encoded 4-field account record.
evmc::bytes32 pack_account_leaf(
    const std::vector<uint8_t>& path_nibbles,
    const Accounts& accounts,
    size_t account_idx,
    const evmc::bytes32& storage_root)
{
    using rlp::BytesView;

    const uint64_t          nonce     = accounts.nonce_at    (account_idx);
    const evmc::uint256be   balance   = accounts.balance_at  (account_idx);
    const evmc::bytes32     code_hash = accounts.code_hash_at(account_idx);

    const auto nonce_rlp   = rlp::encode_u64(nonce);
    const auto balance_rlp = rlp::encode_u256(balance);
    const auto sroot_rlp   = rlp::encode(BytesView{storage_root.bytes,
                                                    sizeof(storage_root.bytes)});
    const auto chash_rlp   = rlp::encode(BytesView{code_hash.bytes,
                                                    sizeof(code_hash.bytes)});
    const auto account_rlp = rlp::encode_list({nonce_rlp, balance_rlp, sroot_rlp, chash_rlp});

    const auto hp_bytes = hex_prefix(path_nibbles, /*leaf=*/true);
    const auto hp_rlp   = rlp::encode(BytesView{hp_bytes});
    const auto val_rlp  = rlp::encode(BytesView{account_rlp});
    const auto leaf_rlp = rlp::encode_list({hp_rlp, val_rlp});

    return keccak_bytes32(leaf_rlp.data(), leaf_rlp.size());
}

// Storage leaf = [HP(path, leaf=true), RLP(slot_value)].
evmc::bytes32 pack_storage_leaf(
    const std::vector<uint8_t>& path_nibbles,
    const Storages& storages,
    size_t storage_idx)
{
    using rlp::BytesView;

    const evmc::bytes32 raw = storages.value_at(storage_idx);
    // The slot value is a 256-bit big-endian integer — RLP-encode with
    // leading zeros trimmed. Reuse encode_u256 by treating bytes32 as
    // uint256be (same layout).
    evmc::uint256be as_u256;
    std::memcpy(as_u256.bytes, raw.bytes, sizeof(raw.bytes));
    const auto value_rlp = rlp::encode_u256(as_u256);

    const auto hp_bytes = hex_prefix(path_nibbles, /*leaf=*/true);
    const auto hp_rlp   = rlp::encode(BytesView{hp_bytes});
    const auto val_rlp  = rlp::encode(BytesView{value_rlp});
    const auto leaf_rlp = rlp::encode_list({hp_rlp, val_rlp});

    return keccak_bytes32(leaf_rlp.data(), leaf_rlp.size());
}

// Extension node = [HP(ext, leaf=false), child_hash].
evmc::bytes32 pack_extension(
    const std::vector<uint8_t>& ext_nibbles,
    const evmc::bytes32& child_hash)
{
    using rlp::BytesView;

    const auto hp_bytes = hex_prefix(ext_nibbles, /*leaf=*/false);
    const auto hp_rlp    = rlp::encode(BytesView{hp_bytes});
    const auto child_rlp = rlp::encode(BytesView{child_hash.bytes,
                                                  sizeof(child_hash.bytes)});
    const auto ext_rlp = rlp::encode_list({hp_rlp, child_rlp});

    return keccak_bytes32(ext_rlp.data(), ext_rlp.size());
}

// Branch node = [c0, c1, …, c15, ""] — 17 elements, last is the unused
// branch-value slot (always empty in modern Ethereum tries).
// An all-zero child encodes as the RLP empty string; otherwise as a
// 32-byte hash string.
evmc::bytes32 pack_branch(const std::array<evmc::bytes32, 16>& children) {
    using rlp::BytesView;

    static constexpr evmc::bytes32 kZero{};

    std::array<rlp::Bytes, 17> slots;
    for (size_t k = 0; k < 16; ++k) {
        if (std::memcmp(&children[k], &kZero, sizeof(kZero)) == 0) {
            slots[k] = rlp::encode(BytesView{});  // RLP empty string = 0x80
        } else {
            slots[k] = rlp::encode(BytesView{children[k].bytes,
                                              sizeof(children[k].bytes)});
        }
    }
    slots[16] = rlp::encode(BytesView{});  // branch value: always empty

    const auto branch_rlp = rlp::encode_list({
        slots[0],  slots[1],  slots[2],  slots[3],
        slots[4],  slots[5],  slots[6],  slots[7],
        slots[8],  slots[9],  slots[10], slots[11],
        slots[12], slots[13], slots[14], slots[15],
        slots[16],
    });

    return keccak_bytes32(branch_rlp.data(), branch_rlp.size());
}

bool is_empty_hash(const evmc::bytes32& h) {
    static constexpr evmc::bytes32 zero{};
    return std::memcmp(&h, &zero, sizeof(h)) == 0;
}

// Abort if the first `walked.size()` nibbles of `hash` don't match the
// nibbles we actually walked to reach the leaf.
void verify_path_prefix(const std::vector<uint8_t>& walked,
                        const evmc::bytes32& hash) {
    for (size_t i = 0; i < walked.size(); ++i) {
        const uint8_t b = hash.bytes[i / 2];
        const uint8_t expected = (i % 2 == 0) ? (b >> 4) : (b & 0x0f);
        if (walked[i] != expected) {
            fatal("state_root: leaf hash prefix doesn't match walked path");
        }
    }
}

// ----- recursive walker -----
//
// `nibbles_walked` is the actual path of nibbles we've taken down the trie
// so far (one byte per nibble, 0..15). It's mutated in-place: pushed
// before recursing into a Node child and popped after. At every Leaf we
// use it to verify that keccak256(address) or keccak256(position) starts
// with exactly those nibbles — catches mis-positioned leaves at parse
// time instead of waiting for the root hash to mismatch.
//
// `owning_address` is non-null only when `kind == Storage` (i.e. we're
// inside the per-account storage subtree pulled in by a state leaf). It
// lets us verify that every storage leaf we see actually belongs to that
// account — the Storages table is shared across the whole block, so a
// malicious or buggy stream could otherwise smuggle in another account's
// slot.
NodeR walk_node(
    const uint8_t*& cursor,
    const Accounts& accounts,
    const Storages& storages,
    TreeKind kind,
    std::vector<uint8_t>& nibbles_walked,
    const evmc::address* owning_address);

// Finalize a top-level NodeR into the trie root hash.
evmc::bytes32 finalize(
    const NodeR& r,
    const Accounts& accounts,
    const Storages& storages)
{
    return std::visit([&](const auto& x) -> evmc::bytes32 {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, EmptyR>) {
            return kEmptyTrieRoot;
        } else if constexpr (std::is_same_v<T, HashR>) {
            return x.hash;
        } else if constexpr (std::is_same_v<T, ExtR>) {
            return pack_extension(x.ext_nibbles, x.hash);
        } else if constexpr (std::is_same_v<T, AccountLeafR>) {
            return pack_account_leaf(x.path_nibbles, accounts, x.account_idx, x.storage_root);
        } else if constexpr (std::is_same_v<T, StorageLeafR>) {
            return pack_storage_leaf(x.path_nibbles, storages, x.storage_idx);
        }
    }, r);
}

// Pack any non-Hash leaf/extension into its hash (for branch construction).
evmc::bytes32 pack_to_hash(
    const NodeR& r,
    const Accounts& accounts,
    const Storages& storages)
{
    return std::visit([&](const auto& x) -> evmc::bytes32 {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, EmptyR>) {
            return evmc::bytes32{};  // sentinel "empty slot" — caller handles
        } else if constexpr (std::is_same_v<T, HashR>) {
            return x.hash;
        } else if constexpr (std::is_same_v<T, ExtR>) {
            return pack_extension(x.ext_nibbles, x.hash);
        } else if constexpr (std::is_same_v<T, AccountLeafR>) {
            return pack_account_leaf(x.path_nibbles, accounts, x.account_idx, x.storage_root);
        } else if constexpr (std::is_same_v<T, StorageLeafR>) {
            return pack_storage_leaf(x.path_nibbles, storages, x.storage_idx);
        }
    }, r);
}

NodeR walk_node(
    const uint8_t*& cursor,
    const Accounts& accounts,
    const Storages& storages,
    TreeKind kind,
    std::vector<uint8_t>& nibbles_walked,
    const evmc::address* owning_address)
{
    const Op op = static_cast<Op>(read_u64_le(cursor));

    // All returns go through the `mk_node<T>(...)` helper above, which
    // uses `variant::emplace<T>` internally. See the helper's comment for
    // the IntelliSense rationale.

    switch (op) {
        case Op::Empty:
            return mk_node<EmptyR>();

        case Op::Hash: {
            evmc::bytes32 h;
            std::memcpy(h.bytes, cursor, sizeof(h.bytes));
            cursor += sizeof(h.bytes);  // 32 B — already 8-aligned
            return mk_node<HashR>(h);
        }

        case Op::ExtensionHash: {
            const uint64_t n = read_u64_le(cursor);
            std::vector<uint8_t> ext;
            ext.reserve(n);
            for (uint64_t i = 0; i < n; ++i) {
                // Each nibble occupies one full u64 slot in the stream —
                // wasteful but trivially 8-aligned.
                ext.push_back(static_cast<uint8_t>(read_u64_le(cursor) & 0x0f));
            }
            evmc::bytes32 h;
            std::memcpy(h.bytes, cursor, sizeof(h.bytes));
            cursor += sizeof(h.bytes);
            return mk_node<ExtR>(std::move(ext), h);
        }

        case Op::Leaf: {
            if (kind == TreeKind::State) {
                const uint64_t idx = read_u64_le(cursor);
                const evmc::address& addr = accounts.address_at(idx);
                const evmc::bytes32 addr_hash =
                    keccak_bytes32(addr.bytes, sizeof(addr.bytes));

                // Check 1: the nibbles we walked match keccak(address)'s prefix.
                verify_path_prefix(nibbles_walked, addr_hash);

                // Recurse into the embedded storage subtree from a fresh
                // empty path; pass the owning address so storage leaves
                // can verify ownership.
                std::vector<uint8_t> storage_walked;
                NodeR storage_subtree = walk_node(
                    cursor, accounts, storages,
                    TreeKind::Storage, storage_walked, &addr);
                const evmc::bytes32 storage_root =
                    finalize(storage_subtree, accounts, storages);

                auto path = nibbles_from(addr_hash, nibbles_walked.size());
                return mk_node<AccountLeafR>(std::move(path),
                                             static_cast<size_t>(idx),
                                             storage_root);
            } else {
                const uint64_t idx = read_u64_le(cursor);
                const evmc::address& storage_addr = storages.address_at(idx);
                const evmc::bytes32& pos = storages.position_at(idx);

                // Check 2: this storage slot really belongs to the account
                // whose subtree we're walking.
                if (owning_address == nullptr
                    || std::memcmp(&storage_addr, owning_address,
                                   sizeof(evmc::address)) != 0) {
                    fatal("state_root: storage leaf address does not match owning account");
                }

                const evmc::bytes32 pos_hash =
                    keccak_bytes32(pos.bytes, sizeof(pos.bytes));

                // Check 1: the nibbles we walked match keccak(position)'s prefix.
                verify_path_prefix(nibbles_walked, pos_hash);

                auto path = nibbles_from(pos_hash, nibbles_walked.size());
                return mk_node<StorageLeafR>(std::move(path),
                                             static_cast<size_t>(idx));
            }
        }

        case Op::Node: {
            std::array<NodeR, 16> children;
            for (uint8_t k = 0; k < 16; ++k) {
                nibbles_walked.push_back(k);
                children[k] = walk_node(cursor, accounts, storages, kind,
                                        nibbles_walked, owning_address);
                nibbles_walked.pop_back();
            }

            // Reduction: count non-empty children + locate the single one.
            int count = 0;
            int single = -1;
            for (int k = 0; k < 16; ++k) {
                if (!std::holds_alternative<EmptyR>(children[k])) {
                    ++count;
                    single = k;
                }
            }

            if (count == 0) {
                return mk_node<EmptyR>();
            }

            if (count == 1) {
                const uint8_t nibble = static_cast<uint8_t>(single);
                NodeR& only = children[single];
                if (auto* leaf = std::get_if<AccountLeafR>(&only)) {
                    AccountLeafR moved = std::move(*leaf);
                    moved.path_nibbles.insert(moved.path_nibbles.begin(), nibble);
                    return mk_node<AccountLeafR>(std::move(moved));
                }
                if (auto* leaf = std::get_if<StorageLeafR>(&only)) {
                    StorageLeafR moved = std::move(*leaf);
                    moved.path_nibbles.insert(moved.path_nibbles.begin(), nibble);
                    return mk_node<StorageLeafR>(std::move(moved));
                }
                if (auto* h = std::get_if<HashR>(&only)) {
                    return mk_node<ExtR>(std::vector<uint8_t>{nibble}, h->hash);
                }
                if (auto* e = std::get_if<ExtR>(&only)) {
                    ExtR moved = std::move(*e);
                    moved.ext_nibbles.insert(moved.ext_nibbles.begin(), nibble);
                    return mk_node<ExtR>(std::move(moved));
                }
                // EmptyR ruled out by count > 0.
            }

            // count >= 2: pack each child to a hash and build a branch.
            std::array<evmc::bytes32, 16> child_hashes{};
            for (int k = 0; k < 16; ++k) {
                child_hashes[k] = pack_to_hash(children[k], accounts, storages);
            }
            return mk_node<HashR>(pack_branch(child_hashes));
        }
    }

    fatal("calculate_state_root: invalid opcode in stream");
}

// Silence -Wunused-function for is_empty_hash on builds that may not
// reach pack_branch's eventual real implementation.
[[maybe_unused]] auto _unused_is_empty_hash = is_empty_hash;

} // namespace

evmc::bytes32 calculate_state_root(
    const uint8_t*& cursor,
    const Accounts& accounts,
    const Storages& storages)
{
    std::vector<uint8_t> nibbles_walked;
    nibbles_walked.reserve(64);  // max trie depth
    NodeR root = walk_node(cursor, accounts, storages,
                           TreeKind::State, nibbles_walked,
                           /*owning_address=*/nullptr);
    return finalize(root, accounts, storages);
}

} // namespace zeg

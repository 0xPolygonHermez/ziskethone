#include "zeg/state_root.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <type_traits>
#include <utility>
#include <vector>

#include "zeg/accounts.hpp"
#include "zeg/fatal.hpp"
#include "zeg/hex_prefix.hpp"
#include "zeg/keccak.hpp"
#include "zeg/rlp.hpp"
#include "zeg/storages.hpp"
#include "zeg/stream.hpp"

namespace zeg {

namespace {

// Pull the StateRoot-nested variant types into local names so the rest
// of this TU reads exactly like before the flatten.
using EmptyR       = StateRoot::EmptyR;
using HashR        = StateRoot::HashR;
using ExtR         = StateRoot::ExtR;
using AccountLeafR = StateRoot::AccountLeafR;
using StorageLeafR = StateRoot::StorageLeafR;
using PhantomLeafR = StateRoot::PhantomLeafR;
using NodeR        = StateRoot::NodeR;
using CacheEntry   = StateRoot::CacheEntry;

// ===== enums & opcodes ======================================================

// Which pass of the trie we're running: the old-root pass writes cache
// entries and runs full validation; the new-root pass reads from the
// cache and skips checks already done during the old-root pass.
enum class WalkPass : uint8_t { OldRoot, NewRoot };

// Which set of values the leaf-packing helpers should fetch from
// Accounts/Storages.
enum class ValueSet : uint8_t { Original, Current };

enum class TreeKind : uint8_t { State, Storage };

// Stream-encoded node opcodes (u64 each, 8-byte aligned).
//
// `Branch` is the single 16-ary branch node. There is no static read-only
// vs read-write distinction any more: the new-root pass derives read-only
// dynamically (a leaf is read-only iff its original == current value; a
// node is read-only iff all its children are), and reuses the cached
// old-root result for read-only subtrees instead of re-hashing them.
enum class Op : uint64_t {
    Empty         = 0,
    Hash          = 1,
    ExtensionHash = 2,
    Leaf          = 3,
    Branch        = 4,
    /// Fallback: carries a sibling leaf inline when Reth omits its
    /// keccak preimage from `witness.keys` so it never became a target
    /// in the sorted Accounts/Storages table. Payload: u64 path_nib_count
    /// + nib_count×u64 (low 4 bits) + u64 value_len + value_len bytes
    /// (pad to 8). The common path (preimage present → enriched into
    /// prestate) goes through bare `Op::Leaf` instead, its table index
    /// derived from the walk counter.
    PhantomLeaf   = 5,
};

// Helper: construct a NodeR holding alternative `T`. We default-construct
// the variant and then `.emplace<T>(...)` rather than relying on
// variant's converting constructor or its `in_place_type` constructor —
// VS Code's IntelliSense parser (a Microsoft EDG fork) does not
// recognise either of those for our variant, even though every real
// compiler does. The emplace member template parses cleanly there.
template <typename T, typename... Args>
NodeR mk_node(Args&&... args) {
    NodeR n;
    n.template emplace<T>(std::forward<Args>(args)...);
    return n;
}

// ===== constants ============================================================

// keccak256(rlp("")) — empty-trie root.
constexpr evmc::bytes32 kEmptyTrieRoot{{
    0x56,0xe8,0x1f,0x17,0x1b,0xcc,0x55,0xa6,
    0xff,0x83,0x45,0xe6,0x92,0xc0,0xf8,0x6e,
    0x5b,0x48,0xe0,0x1b,0x99,0x6c,0xad,0xc0,
    0x01,0x62,0x2f,0xb5,0xe3,0x63,0xb4,0x21,
}};

// keccak256("") — code hash of an account with no code.
constexpr evmc::bytes32 kEmptyCodeHash{{
    0xc5,0xd2,0x46,0x01,0x86,0xf7,0x23,0x3c,
    0x92,0x7e,0x7d,0xb2,0xdc,0xc7,0x03,0xc0,
    0xe5,0x00,0xb6,0x53,0xca,0x82,0x27,0x3b,
    0x7b,0xfa,0xd8,0x04,0x5d,0x85,0xa4,0x70,
}};

// ===== helpers ==============================================================

bool is_empty_account(uint64_t nonce,
                      const evmc::uint256be& balance,
                      const evmc::bytes32& code_hash) {
    if (nonce != 0) return false;
    static constexpr evmc::uint256be kZeroBalance{};
    if (std::memcmp(&balance, &kZeroBalance, sizeof(balance)) != 0) return false;
    if (std::memcmp(&code_hash, &kEmptyCodeHash, sizeof(code_hash)) != 0) return false;
    return true;
}

bool is_zero_value(const evmc::bytes32& v) {
    static constexpr evmc::bytes32 kZero{};
    return std::memcmp(&v, &kZero, sizeof(v)) == 0;
}

std::vector<uint8_t> nibbles_from(const evmc::bytes32& hash, size_t start_nibble) {
    std::vector<uint8_t> out;
    out.reserve(64 - start_nibble);
    for (size_t i = start_nibble; i < 64; ++i) {
        const uint8_t b = hash.bytes[i / 2];
        out.push_back(static_cast<uint8_t>((i % 2 == 0) ? (b >> 4) : (b & 0x0f)));
    }
    return out;
}

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

// ===== pack* (RLP + HP + keccak) ============================================
//
// Each node type has a `build_*_rlp` helper that produces the node's full
// RLP encoding (no hashing) and a thin `pack_*` wrapper that returns its
// keccak256. The split lets `pack_to_child_ref` apply the Yellow-Paper
// cap function: if the node's RLP is < 32 bytes embed it inline into the
// parent slot, otherwise reference it by its 32-byte hash.

rlp::Bytes build_account_leaf_rlp(
    const std::vector<uint8_t>& path_nibbles,
    const Accounts& accounts,
    size_t account_idx,
    const evmc::bytes32& storage_root,
    ValueSet which)
{
    using rlp::BytesView;

    const uint64_t        nonce =
        (which == ValueSet::Original) ? accounts.nonce_orig_at(account_idx)
                                      : accounts.nonce_at     (account_idx);
    const evmc::uint256be balance =
        (which == ValueSet::Original) ? accounts.balance_orig_at(account_idx)
                                      : accounts.balance_at     (account_idx);
    const evmc::bytes32   code_hash =
        (which == ValueSet::Original) ? accounts.code_hash_orig_at(account_idx)
                                      : accounts.code_hash_at     (account_idx);

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
    return rlp::encode_list({hp_rlp, val_rlp});
}

rlp::Bytes build_storage_leaf_rlp(
    const std::vector<uint8_t>& path_nibbles,
    const Storages& storages,
    size_t storage_idx,
    ValueSet which)
{
    using rlp::BytesView;

    const evmc::bytes32 raw =
        (which == ValueSet::Original) ? storages.value_orig_at(storage_idx)
                                      : storages.value_at     (storage_idx);
    evmc::uint256be as_u256;
    std::memcpy(as_u256.bytes, raw.bytes, sizeof(raw.bytes));
    const auto value_rlp = rlp::encode_u256(as_u256);

    const auto hp_bytes = hex_prefix(path_nibbles, /*leaf=*/true);
    const auto hp_rlp   = rlp::encode(BytesView{hp_bytes});
    const auto val_rlp  = rlp::encode(BytesView{value_rlp});
    return rlp::encode_list({hp_rlp, val_rlp});
}

rlp::Bytes build_extension_rlp(
    const std::vector<uint8_t>& ext_nibbles,
    const evmc::bytes32& child_hash)
{
    using rlp::BytesView;

    const auto hp_bytes = hex_prefix(ext_nibbles, /*leaf=*/false);
    const auto hp_rlp    = rlp::encode(BytesView{hp_bytes});
    const auto child_rlp = rlp::encode(BytesView{child_hash.bytes,
                                                  sizeof(child_hash.bytes)});
    return rlp::encode_list({hp_rlp, child_rlp});
}

evmc::bytes32 pack_account_leaf(
    const std::vector<uint8_t>& path_nibbles,
    const Accounts& accounts,
    size_t account_idx,
    const evmc::bytes32& storage_root,
    ValueSet which)
{
    const auto rlp = build_account_leaf_rlp(path_nibbles, accounts, account_idx,
                                            storage_root, which);
    return keccak256_bytes32(rlp.data(), rlp.size());
}

evmc::bytes32 pack_storage_leaf(
    const std::vector<uint8_t>& path_nibbles,
    const Storages& storages,
    size_t storage_idx,
    ValueSet which)
{
    const auto rlp = build_storage_leaf_rlp(path_nibbles, storages, storage_idx, which);
    return keccak256_bytes32(rlp.data(), rlp.size());
}

evmc::bytes32 pack_extension(
    const std::vector<uint8_t>& ext_nibbles,
    const evmc::bytes32& child_hash)
{
    const auto rlp = build_extension_rlp(ext_nibbles, child_hash);
    return keccak256_bytes32(rlp.data(), rlp.size());
}

rlp::Bytes build_phantom_leaf_rlp(
    const std::vector<uint8_t>& path_nibbles,
    const std::vector<uint8_t>& value_rlp)
{
    using rlp::BytesView;
    const auto hp_bytes = hex_prefix(path_nibbles, /*leaf=*/true);
    const auto hp_rlp   = rlp::encode(BytesView{hp_bytes});
    const auto val_rlp  = rlp::encode(BytesView{value_rlp});
    return rlp::encode_list({hp_rlp, val_rlp});
}

evmc::bytes32 pack_phantom_leaf(
    const std::vector<uint8_t>& path_nibbles,
    const std::vector<uint8_t>& value_rlp)
{
    const auto rlp = build_phantom_leaf_rlp(path_nibbles, value_rlp);
    return keccak256_bytes32(rlp.data(), rlp.size());
}

// Return the bytes that should occupy this child's slot inside a parent
// branch node. Implements the MPT cap function (Yellow Paper App. D):
//   * EmptyR → RLP empty string (`{0x80}`).
//   * HashR / ExtR → 33-byte RLP-encoded 32-byte hash (the prover sent
//     us a hash already, so the subtree's RLP size is either unknown
//     or guaranteed ≥ 32; embed it as a hash reference).
//   * AccountLeafR / StorageLeafR → compute the leaf's full RLP; if it
//     is < 32 bytes embed it inline (it's a 2-element list, which is a
//     valid RLP list element on its own), otherwise hash it and embed
//     the hash reference.
rlp::Bytes pack_to_child_ref(const NodeR& r,
                             const Accounts& accounts,
                             const Storages& storages,
                             ValueSet which)
{
    using rlp::BytesView;

    return std::visit([&](const auto& x) -> rlp::Bytes {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, EmptyR>) {
            return rlp::Bytes{0x80};
        } else if constexpr (std::is_same_v<T, HashR>) {
            return rlp::encode(BytesView{x.hash.bytes, sizeof(x.hash.bytes)});
        } else if constexpr (std::is_same_v<T, ExtR>) {
            const auto node_rlp = build_extension_rlp(x.ext_nibbles, x.hash);
            // Extension wrapping a 32-byte hash is always ≥ 35 bytes,
            // so the inline branch is unreachable in practice — but the
            // check stays so the rule is stated in one place.
            if (node_rlp.size() < 32) return node_rlp;
            const auto h = keccak256_bytes32(node_rlp.data(), node_rlp.size());
            return rlp::encode(BytesView{h.bytes, sizeof(h.bytes)});
        } else if constexpr (std::is_same_v<T, AccountLeafR>) {
            const auto node_rlp = build_account_leaf_rlp(
                x.path_nibbles, accounts, x.account_idx, x.storage_root, which);
            if (node_rlp.size() < 32) return node_rlp;
            const auto h = keccak256_bytes32(node_rlp.data(), node_rlp.size());
            return rlp::encode(BytesView{h.bytes, sizeof(h.bytes)});
        } else if constexpr (std::is_same_v<T, StorageLeafR>) {
            const auto node_rlp = build_storage_leaf_rlp(
                x.path_nibbles, storages, x.storage_idx, which);
            if (node_rlp.size() < 32) return node_rlp;
            const auto h = keccak256_bytes32(node_rlp.data(), node_rlp.size());
            return rlp::encode(BytesView{h.bytes, sizeof(h.bytes)});
        } else if constexpr (std::is_same_v<T, PhantomLeafR>) {
            const auto node_rlp = build_phantom_leaf_rlp(x.path_nibbles, x.value_rlp);
            if (node_rlp.size() < 32) return node_rlp;
            const auto h = keccak256_bytes32(node_rlp.data(), node_rlp.size());
            return rlp::encode(BytesView{h.bytes, sizeof(h.bytes)});
        }
    }, r);
}

// Assemble a branch node from 16 pre-computed child slot byte-blobs
// (each is either a 1-byte 0x80, an inline RLP list, or a 33-byte
// RLP-encoded hash). The 17th slot is the always-empty branch value.
evmc::bytes32 pack_branch(const std::array<rlp::Bytes, 16>& child_refs) {
    using rlp::BytesView;

    static const rlp::Bytes kEmptyValueSlot{0x80};

    const auto branch_rlp = rlp::encode_list({
        BytesView{child_refs[0]},  BytesView{child_refs[1]},
        BytesView{child_refs[2]},  BytesView{child_refs[3]},
        BytesView{child_refs[4]},  BytesView{child_refs[5]},
        BytesView{child_refs[6]},  BytesView{child_refs[7]},
        BytesView{child_refs[8]},  BytesView{child_refs[9]},
        BytesView{child_refs[10]}, BytesView{child_refs[11]},
        BytesView{child_refs[12]}, BytesView{child_refs[13]},
        BytesView{child_refs[14]}, BytesView{child_refs[15]},
        BytesView{kEmptyValueSlot},
    });

    return keccak256_bytes32(branch_rlp.data(), branch_rlp.size());
}

// ===== walk context =========================================================

// All state the walker / reduce_branch need, borrowed by reference
// from the StateRoot that drives them. The walker uses ctx.cache /
// ctx.cache_read_pos to write or read cache entries; the StateRoot
// member functions set up the right pass / ValueSet before calling.
struct WalkContext {
    const Accounts&            accounts;
    const Storages&            storages;
    std::vector<CacheEntry>&   cache;
    std::size_t&               cache_read_pos;
    WalkPass                   pass;
    ValueSet                   which;
    // Running leaf counters. `Op::Leaf` no longer carries an index; the
    // table is sorted in trie-walk order, so the n-th state/storage leaf
    // visited IS Accounts[n] / Storages[n]. Each leaf consumes the next
    // counter value. The old-root pass asserts both reach size() (every
    // row appears as exactly one leaf — none repeated, none missing).
    std::size_t&               next_state_idx;
    std::size_t&               next_storage_idx;
};

// Forward declarations.
NodeR walk_node(
    const uint8_t*& cursor,
    WalkContext& ctx,
    TreeKind kind,
    std::vector<uint8_t>& nibbles_walked,
    const evmc::address* owning_address,
    bool readonly_mode);

evmc::bytes32 finalize(const NodeR& r,
                       const Accounts& accounts,
                       const Storages& storages,
                       ValueSet which);

// ===== walker + reduction + finalize ========================================

evmc::bytes32 finalize(const NodeR& r,
                       const Accounts& accounts,
                       const Storages& storages,
                       ValueSet which)
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
            return pack_account_leaf(x.path_nibbles, accounts, x.account_idx,
                                     x.storage_root, which);
        } else if constexpr (std::is_same_v<T, StorageLeafR>) {
            return pack_storage_leaf(x.path_nibbles, storages, x.storage_idx, which);
        } else if constexpr (std::is_same_v<T, PhantomLeafR>) {
            return pack_phantom_leaf(x.path_nibbles, x.value_rlp);
        }
    }, r);
}

NodeR reduce_branch(std::array<NodeR, 16> children, WalkContext& ctx) {
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
        if (auto* leaf = std::get_if<PhantomLeafR>(&only)) {
            PhantomLeafR moved = std::move(*leaf);
            moved.path_nibbles.insert(moved.path_nibbles.begin(), nibble);
            return mk_node<PhantomLeafR>(std::move(moved));
        }
        if (auto* h = std::get_if<HashR>(&only)) {
            return mk_node<ExtR>(std::vector<uint8_t>{nibble}, h->hash);
        }
        if (auto* e = std::get_if<ExtR>(&only)) {
            ExtR moved = std::move(*e);
            moved.ext_nibbles.insert(moved.ext_nibbles.begin(), nibble);
            return mk_node<ExtR>(std::move(moved));
        }
    }

    std::array<rlp::Bytes, 16> child_refs;
    for (int k = 0; k < 16; ++k) {
        child_refs[k] = pack_to_child_ref(children[k], ctx.accounts,
                                          ctx.storages, ctx.which);
    }
    return mk_node<HashR>(pack_branch(child_refs));
}

NodeR walk_node(
    const uint8_t*& cursor,
    WalkContext& ctx,
    TreeKind kind,
    std::vector<uint8_t>& nibbles_walked,
    const evmc::address* owning_address,
    bool readonly_mode)
{
    const Op op = static_cast<Op>(read_u64_le(cursor));

    switch (op) {
        case Op::Empty:
            return mk_node<EmptyR>();

        case Op::Hash: {
            evmc::bytes32 h;
            std::memcpy(h.bytes, cursor, sizeof(h.bytes));
            cursor += sizeof(h.bytes);  // 32 B — already 8-aligned
            // An Op::Hash stands in for an UNTOUCHED subtree only — i.e.
            // one that contains no Accounts/Storages table rows. It does
            // not advance the leaf counters. If the witness were missing a
            // node over read-only table rows, the encoder would still emit
            // Op::Hash here, but then those rows would have no leaf and the
            // old-root-pass `count == size()` check fatals (strict: an
            // incomplete witness is rejected, not silently skipped).
            return mk_node<HashR>(h);
        }

        case Op::ExtensionHash: {
            const uint64_t n = read_u64_le(cursor);
            std::vector<uint8_t> ext;
            ext.reserve(n);
            for (uint64_t i = 0; i < n; ++i) {
                ext.push_back(static_cast<uint8_t>(read_u64_le(cursor) & 0x0f));
            }
            evmc::bytes32 h;
            std::memcpy(h.bytes, cursor, sizeof(h.bytes));
            cursor += sizeof(h.bytes);
            return mk_node<ExtR>(std::move(ext), h);
        }

        case Op::Leaf: {
            if (kind == TreeKind::State) {
                // No index in the stream: the n-th state leaf visited is
                // Accounts[n] (the table is sorted in trie-walk order).
                // Bounds-guard catches a stream with more leaves than
                // accounts; the end-of-old-root-pass check catches fewer.
                if (ctx.next_state_idx >= ctx.accounts.size()) {
                    fatal("state_root: more state leaves than accounts");
                }
                const uint64_t idx = ctx.next_state_idx++;

                if (ctx.pass == WalkPass::OldRoot
                    && readonly_mode
                    && !ctx.accounts.is_read_only_at(idx)) {
                    fatal("state_root: read-write account leaf under a NodeR subtree");
                }

                const evmc::address& addr = ctx.accounts.address_at(idx);
                const evmc::bytes32 addr_hash =
                    keccak256_bytes32(addr.bytes, sizeof(addr.bytes));

                if (ctx.pass == WalkPass::OldRoot) {
                    verify_path_prefix(nibbles_walked, addr_hash);
                }

                std::vector<uint8_t> storage_walked;
                NodeR storage_subtree = walk_node(
                    cursor, ctx, TreeKind::Storage, storage_walked,
                    &addr, readonly_mode);
                const evmc::bytes32 storage_root =
                    finalize(storage_subtree, ctx.accounts, ctx.storages, ctx.which);
                if (std::getenv("ZEG_DUMP_SROOT") != nullptr
                    && ctx.pass == WalkPass::NewRoot) {
                    std::fprintf(stderr, "SROOT %llu addr=", (unsigned long long)idx);
                    for (uint8_t b : addr.bytes) std::fprintf(stderr, "%02x", b);
                    std::fprintf(stderr, " sroot=");
                    for (uint8_t b : storage_root.bytes) std::fprintf(stderr, "%02x", b);
                    std::fprintf(stderr, "\n");
                }

                const uint64_t nonce =
                    (ctx.which == ValueSet::Original) ? ctx.accounts.nonce_orig_at(idx)
                                                      : ctx.accounts.nonce_at     (idx);
                const evmc::uint256be balance =
                    (ctx.which == ValueSet::Original) ? ctx.accounts.balance_orig_at(idx)
                                                      : ctx.accounts.balance_at     (idx);
                const evmc::bytes32 code_hash =
                    (ctx.which == ValueSet::Original) ? ctx.accounts.code_hash_orig_at(idx)
                                                      : ctx.accounts.code_hash_at     (idx);
                if (is_empty_account(nonce, balance, code_hash)) {
                    return mk_node<EmptyR>();
                }

                auto path = nibbles_from(addr_hash, nibbles_walked.size());
                return mk_node<AccountLeafR>(std::move(path),
                                             static_cast<size_t>(idx),
                                             storage_root);
            } else {
                // No index in the stream: the n-th storage leaf visited
                // is Storages[n]. The single global counter stays
                // monotonic because the table is sorted by (keccak addr,
                // keccak slot) and the walk visits account-after-account,
                // slot-after-slot.
                if (ctx.next_storage_idx >= ctx.storages.size()) {
                    fatal("state_root: more storage leaves than storage slots");
                }
                const uint64_t idx = ctx.next_storage_idx++;

                if (ctx.pass == WalkPass::OldRoot
                    && readonly_mode
                    && !ctx.storages.is_read_only_at(idx)) {
                    fatal("state_root: read-write storage leaf under a NodeR subtree");
                }

                const evmc::address& storage_addr = ctx.storages.address_at(idx);
                const evmc::bytes32& pos = ctx.storages.position_at(idx);

                if (ctx.pass == WalkPass::OldRoot) {
                    if (owning_address == nullptr
                        || std::memcmp(&storage_addr, owning_address,
                                       sizeof(evmc::address)) != 0) {
                        fatal("state_root: storage leaf address does not match owning account");
                    }
                }

                const evmc::bytes32 pos_hash =
                    keccak256_bytes32(pos.bytes, sizeof(pos.bytes));

                if (ctx.pass == WalkPass::OldRoot) {
                    verify_path_prefix(nibbles_walked, pos_hash);
                }

                const evmc::bytes32 value =
                    (ctx.which == ValueSet::Original) ? ctx.storages.value_orig_at(idx)
                                                      : ctx.storages.value_at     (idx);
                if (is_zero_value(value)) {
                    return mk_node<EmptyR>();
                }

                auto path = nibbles_from(pos_hash, nibbles_walked.size());
                return mk_node<StorageLeafR>(std::move(path),
                                             static_cast<size_t>(idx));
            }
        }

        case Op::PhantomLeaf: {
            const uint64_t n = read_u64_le(cursor);
            std::vector<uint8_t> path;
            path.reserve(n);
            for (uint64_t i = 0; i < n; ++i) {
                path.push_back(static_cast<uint8_t>(read_u64_le(cursor) & 0x0f));
            }
            const uint64_t value_len = read_u64_le(cursor);
            std::vector<uint8_t> value(cursor, cursor + value_len);
            cursor += value_len;
            align_to_u64(cursor, value_len);
            return mk_node<PhantomLeafR>(std::move(path), std::move(value));
        }

        case Op::Branch: {
            // Single 16-ary branch — no static read-only marking, no
            // partial cache; every child is walked in both passes.
            // (The read-only-reuse optimization is reintroduced in a
            // follow-up via a per-node result cache keyed on walk order.)
            std::array<NodeR, 16> children;
            for (uint8_t k = 0; k < 16; ++k) {
                nibbles_walked.push_back(k);
                children[k] = walk_node(cursor, ctx, kind, nibbles_walked,
                                        owning_address, /*readonly=*/false);
                nibbles_walked.pop_back();
            }
            return reduce_branch(std::move(children), ctx);
        }
    }

    fatal("state_root: invalid opcode in stream");
}

} // namespace

// ============================================================================
// StateRoot — public methods
// ============================================================================

StateRoot::StateRoot(const uint8_t*& cursor,
                     const Accounts& accounts,
                     const Storages& storages)
    : accounts_(accounts),
      storages_(storages),
      start_cursor_(cursor)
{
    std::size_t next_state_idx = 0, next_storage_idx = 0;
    WalkContext ctx{accounts_, storages_, cache_, cache_read_pos_,
                    WalkPass::OldRoot, ValueSet::Original,
                    next_state_idx, next_storage_idx};
    std::vector<uint8_t> nibbles_walked;
    nibbles_walked.reserve(64);  // max trie depth
    NodeR root = walk_node(cursor, ctx, TreeKind::State, nibbles_walked,
                           /*owning_address=*/nullptr, /*readonly_mode=*/false);
    old_root_ = finalize(root, accounts_, storages_, ValueSet::Original);

    // Bijection check (pre-block only): every Accounts / Storages row must
    // appear as exactly one leaf in the pre-block trie. The per-leaf
    // bounds-guard already rejected a stream with too MANY leaves; these
    // assertions reject too FEW. Together they pin every table row's
    // original value into old_root_ (which is matched against the trusted
    // parent anchor), closing the read-only-leaf → Op::Hash substitution
    // gap. The post-block pass reuses this validated structure, so it is
    // not re-checked there.
    if (next_state_idx != accounts_.size()) {
        fatal("state_root: not every account appears as a pre-block leaf");
    }
    if (next_storage_idx != storages_.size()) {
        fatal("state_root: not every storage slot appears as a pre-block leaf");
    }
}

evmc::bytes32 StateRoot::calculate_new_state_root() {
    // Read-only reuse precondition: the new-root pass replays the cached
    // read-only (NodeR-under-NodeRW) subtrees from the old-root pass and
    // never re-walks them. That is only sound if no read-only row changed
    // during execution — otherwise a cached node would embed the stale
    // value and the new root would silently diverge. Enforce it here,
    // where the reuse happens, so the check can't be skipped or reordered
    // by callers. (Originals come from the stream; current values are
    // final once execution has run, which it has by the time the new root
    // is computed.)
    accounts_.check_read_only_unchanged();
    storages_.check_read_only_unchanged();

    cache_read_pos_ = 0;
    const uint8_t* cursor = start_cursor_;
    // Fresh counters for this pass. They still run (so read-write leaves
    // outside cached subtrees get the right table index), advanced through
    // cached subtrees via the per-entry leaf counts. No end-of-pass check:
    // the pre-block pass already validated the bijection.
    std::size_t next_state_idx = 0, next_storage_idx = 0;
    WalkContext ctx{accounts_, storages_, cache_, cache_read_pos_,
                    WalkPass::NewRoot, ValueSet::Current,
                    next_state_idx, next_storage_idx};
    std::vector<uint8_t> nibbles_walked;
    nibbles_walked.reserve(64);
    NodeR root = walk_node(cursor, ctx, TreeKind::State, nibbles_walked,
                           /*owning_address=*/nullptr, /*readonly_mode=*/false);
    return finalize(root, accounts_, storages_, ValueSet::Current);
}

} // namespace zeg

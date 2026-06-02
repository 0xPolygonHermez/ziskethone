#include "zeg/state_root.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
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
#include "zeg/trie_node.hpp"

namespace zeg {

namespace {

// ===== enums & opcodes ======================================================

// Which set of values the leaf-packing helpers fetch from Accounts/Storages.
enum class ValueSet : uint8_t { Original, Current };

enum class TreeKind : uint8_t { State, Storage };

// Stream-encoded node opcodes (u64 each, 8-byte aligned). See BINARY_FORMAT.md.
enum class Op : uint64_t {
    Empty         = 0,
    Hash          = 1,
    ExtensionHash = 2,
    Leaf          = 3,
    Branch        = 4,
    PhantomLeaf   = 5,
};

// ===== helpers ==============================================================

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
// branch node (MPT cap function — Yellow Paper App. D).
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

// Assemble a branch node from 16 pre-computed child slot byte-blobs.
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

// Reduce 16 child results into the branch's own result, applying the MPT
// fold: a single non-empty child collapses into an extension / extended
// leaf; otherwise the children are packed into a 16-ary branch hash.
NodeR reduce_branch(const std::array<const NodeR*, 16>& children,
                    const Accounts& accounts,
                    const Storages& storages,
                    ValueSet which)
{
    int count = 0;
    int single = -1;
    for (int k = 0; k < 16; ++k) {
        if (!std::holds_alternative<EmptyR>(*children[k])) {
            ++count;
            single = k;
        }
    }

    if (count == 0) {
        return mk_node<EmptyR>();
    }

    if (count == 1) {
        const uint8_t nibble = static_cast<uint8_t>(single);
        const NodeR& only = *children[single];
        if (const auto* leaf = std::get_if<AccountLeafR>(&only)) {
            AccountLeafR copy = *leaf;
            copy.path_nibbles.insert(copy.path_nibbles.begin(), nibble);
            return mk_node<AccountLeafR>(std::move(copy));
        }
        if (const auto* leaf = std::get_if<StorageLeafR>(&only)) {
            StorageLeafR copy = *leaf;
            copy.path_nibbles.insert(copy.path_nibbles.begin(), nibble);
            return mk_node<StorageLeafR>(std::move(copy));
        }
        if (const auto* leaf = std::get_if<PhantomLeafR>(&only)) {
            PhantomLeafR copy = *leaf;
            copy.path_nibbles.insert(copy.path_nibbles.begin(), nibble);
            return mk_node<PhantomLeafR>(std::move(copy));
        }
        if (const auto* h = std::get_if<HashR>(&only)) {
            return mk_node<ExtR>(std::vector<uint8_t>{nibble}, h->hash);
        }
        if (const auto* e = std::get_if<ExtR>(&only)) {
            ExtR copy = *e;
            copy.ext_nibbles.insert(copy.ext_nibbles.begin(), nibble);
            return mk_node<ExtR>(std::move(copy));
        }
    }

    std::array<rlp::Bytes, 16> child_refs;
    for (int k = 0; k < 16; ++k) {
        child_refs[k] = pack_to_child_ref(*children[k], accounts, storages, which);
    }
    return mk_node<HashR>(pack_branch(child_refs));
}

// ===== build pass (stream -> node array) ====================================

// Borrowed state for the old-root build walk.
struct BuildCtx {
    Accounts&                accounts;
    Storages&                storages;
    std::vector<BranchNode>& branch_nodes;
    std::vector<NodeR>&      aux;
    std::size_t              next_state_idx;
    std::size_t              next_storage_idx;
    std::size_t              node_limit;
};

// The result-node of a static EmptyR child (shared, read-only).
const NodeR& empty_result() {
    static const NodeR kEmpty = mk_node<EmptyR>();
    return kEmpty;
}

// Pointer to a child's current cached result. Valid for both passes:
// branch/aux results live in StateRoot's vectors, leaf results on the rows
// (all pre-reserved or appended before use). Tables' `leaf_` is pre-reserved
// so these pointers stay stable; `branch_nodes`/`aux` only grow during build,
// and callers gather these pointers AFTER all siblings are built (so no
// intervening reallocation invalidates them before they are consumed).
const NodeR* result_ptr(const Child& c,
                        const std::vector<BranchNode>& branch_nodes,
                        const std::vector<NodeR>& aux,
                        const Accounts& accounts,
                        const Storages& storages) {
    switch (c.type) {
        case NodeType::Empty:        return &empty_result();
        case NodeType::Branch:       return &branch_nodes[c.idx].cached;
        case NodeType::Account:      return accounts.cached_at(c.idx);
        case NodeType::Storage:      return storages.cached_at(c.idx);
        case NodeType::Hash:
        case NodeType::ExtensionHash:
        case NodeType::PhantomLeaf:  return &aux[c.idx];
    }
    fatal("state_root: invalid node type");
}

uint32_t aux_push(BuildCtx& ctx, NodeR n) {
    if (ctx.branch_nodes.size() + ctx.aux.size() >= ctx.node_limit) {
        fatal("state_root: more nodes than declared (numberOfNodes overflow)");
    }
    ctx.aux.push_back(std::move(n));
    return static_cast<uint32_t>(ctx.aux.size() - 1);
}

// Walk one node from the stream, materialize it (and its subtree) into the
// node array / tables using ORIGINAL values, and return its Child link.
Child build_node(const uint8_t*& cursor,
                 BuildCtx& ctx,
                 TreeKind kind,
                 std::vector<uint8_t>& walked,
                 const evmc::address* owning_address)
{
    const Op op = static_cast<Op>(read_u64_le(cursor));

    switch (op) {
        case Op::Empty:
            return Child{NodeType::Empty, 0};

        case Op::Hash: {
            evmc::bytes32 h;
            std::memcpy(h.bytes, cursor, sizeof(h.bytes));
            cursor += sizeof(h.bytes);  // 32 B — already 8-aligned
            return Child{NodeType::Hash, aux_push(ctx, mk_node<HashR>(h))};
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
            return Child{NodeType::ExtensionHash,
                         aux_push(ctx, mk_node<ExtR>(std::move(ext), h))};
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
            return Child{NodeType::PhantomLeaf,
                         aux_push(ctx, mk_node<PhantomLeafR>(std::move(path), std::move(value)))};
        }

        case Op::Leaf: {
            if (kind == TreeKind::State) {
                // address(20) pad(4) balance(u256be,32) nonce(u64) code_hash(32)
                evmc::address addr;
                std::memcpy(addr.bytes, cursor, sizeof(addr.bytes));
                cursor += sizeof(addr.bytes) + 4;
                evmc::uint256be balance;
                std::memcpy(balance.bytes, cursor, sizeof(balance.bytes));
                cursor += sizeof(balance.bytes);
                const uint64_t nonce = read_u64_le(cursor);
                evmc::bytes32 code_hash;
                std::memcpy(code_hash.bytes, cursor, sizeof(code_hash.bytes));
                cursor += sizeof(code_hash.bytes);

                const size_t idx = ctx.next_state_idx++;
                const size_t a = ctx.accounts.append(addr, nonce, balance, code_hash);
                if (a != idx) fatal("state_root: account append index desync");

                const evmc::bytes32 addr_hash =
                    keccak256_bytes32(addr.bytes, sizeof(addr.bytes));
                // Bind the payload address to its trie position.
                verify_path_prefix(walked, addr_hash);

                // Build the per-account storage subtree (`addr` is a stable
                // local for the duration of the nested walk).
                std::vector<uint8_t> storage_walked;
                const Child storage_child = build_node(
                    cursor, ctx, TreeKind::Storage, storage_walked, &addr);
                const evmc::bytes32 storage_root = finalize(
                    *result_ptr(storage_child, ctx.branch_nodes, ctx.aux,
                                ctx.accounts, ctx.storages),
                    ctx.accounts, ctx.storages, ValueSet::Original);

                auto nib = nibbles_from(addr_hash, walked.size());
                ctx.accounts.build_value(idx, nib, addr_hash, storage_child, storage_root);
                return Child{NodeType::Account, static_cast<uint32_t>(idx)};
            } else {
                // position(32) value(32); owning address from the account leaf.
                if (owning_address == nullptr) {
                    fatal("state_root: storage leaf outside any account");
                }
                evmc::bytes32 position;
                std::memcpy(position.bytes, cursor, sizeof(position.bytes));
                cursor += sizeof(position.bytes);
                evmc::bytes32 value;
                std::memcpy(value.bytes, cursor, sizeof(value.bytes));
                cursor += sizeof(value.bytes);

                const size_t idx = ctx.next_storage_idx++;
                const size_t a = ctx.storages.append(*owning_address, position, value);
                if (a != idx) fatal("state_root: storage append index desync");

                const evmc::bytes32 pos_hash =
                    keccak256_bytes32(position.bytes, sizeof(position.bytes));
                verify_path_prefix(walked, pos_hash);

                auto nib = nibbles_from(pos_hash, walked.size());
                ctx.storages.build_value(idx, nib, pos_hash);
                return Child{NodeType::Storage, static_cast<uint32_t>(idx)};
            }
        }

        case Op::Branch: {
            BranchNode bn;
            for (uint8_t k = 0; k < 16; ++k) {
                walked.push_back(k);
                bn.children[k] = build_node(cursor, ctx, kind, walked, owning_address);
                walked.pop_back();
            }
            // Gather child results AFTER every child is built (no further
            // pushes happen before reduce_branch consumes them).
            std::array<const NodeR*, 16> child_results;
            for (int k = 0; k < 16; ++k) {
                child_results[k] = result_ptr(bn.children[k], ctx.branch_nodes,
                                              ctx.aux, ctx.accounts, ctx.storages);
            }
            bn.cached = reduce_branch(child_results, ctx.accounts, ctx.storages,
                                      ValueSet::Original);

            if (ctx.branch_nodes.size() + ctx.aux.size() >= ctx.node_limit) {
                fatal("state_root: more nodes than declared (numberOfNodes overflow)");
            }
            ctx.branch_nodes.push_back(std::move(bn));
            return Child{NodeType::Branch,
                         static_cast<uint32_t>(ctx.branch_nodes.size() - 1)};
        }
    }

    fatal("state_root: invalid opcode in stream");
}

// ===== eval pass (node array -> new root) ===================================

struct EvalCtx {
    Accounts&                accounts;
    Storages&                storages;
    std::vector<BranchNode>& branch_nodes;
    std::vector<NodeR>&      aux;
};

// Walk one node of the materialized array against CURRENT values. Returns a
// pointer to the node's current result and whether it is read-only (== its
// old-root result). Read-only nodes reuse their cached result; changed ones
// are recomputed. No vector grows here, so the returned pointers stay valid.
std::pair<const NodeR*, bool> eval_node(const Child& c, EvalCtx& ctx, std::size_t depth) {
    switch (c.type) {
        case NodeType::Empty:
            return {&empty_result(), true};

        case NodeType::Hash:
        case NodeType::ExtensionHash:
        case NodeType::PhantomLeaf:
            // Untouched subtree/leaf — fixed result, always read-only.
            return {&ctx.aux[c.idx], true};

        case NodeType::Account: {
            const size_t idx = c.idx;
            const Child sc = ctx.accounts.storage_root_child_at(idx);
            const auto [sres, storage_ro] = eval_node(sc, ctx, 0);
            const evmc::bytes32 storage_root =
                finalize(*sres, ctx.accounts, ctx.storages, ValueSet::Current);
            auto nib = nibbles_from(ctx.accounts.addr_hash_at(idx), depth);
            const NodeR* r = ctx.accounts.update_value(idx, nib, storage_root);
            const bool read_only = ctx.accounts.fields_unchanged_at(idx) && storage_ro;
            return {r, read_only};
        }

        case NodeType::Storage: {
            const size_t idx = c.idx;
            auto nib = nibbles_from(ctx.storages.pos_hash_at(idx), depth);
            const NodeR* r = ctx.storages.update_value(idx, nib);
            return {r, ctx.storages.value_unchanged_at(idx)};
        }

        case NodeType::Branch: {
            BranchNode& bn = ctx.branch_nodes[c.idx];
            std::array<const NodeR*, 16> child_results;
            bool all_ro = true;
            for (uint8_t k = 0; k < 16; ++k) {
                const auto [cr, cro] = eval_node(bn.children[k], ctx, depth + 1);
                child_results[k] = cr;
                all_ro = all_ro && cro;
            }
            if (all_ro) {
                return {&bn.cached, true};
            }
            bn.cached = reduce_branch(child_results, ctx.accounts, ctx.storages,
                                      ValueSet::Current);
            return {&bn.cached, false};
        }
    }
    fatal("state_root: invalid node type");
}

} // namespace

// ============================================================================
// StateRoot — public methods
// ============================================================================

StateRoot::StateRoot(const uint8_t*& cursor,
                     Accounts& accounts,
                     Storages& storages,
                     uint64_t gas_limit)
    : accounts_(accounts),
      storages_(storages)
{
    // Section header: three u64 counts. numberOfAccounts / numberOfStorages
    // are exact WITNESS counts; numberOfNodes is a conservative upper bound
    // (the encoder emits stream_len/8) used as the node-array ceiling.
    const uint64_t num_nodes    = read_u64_le(cursor);
    const uint64_t num_accounts = read_u64_le(cursor);
    const uint64_t num_storages = read_u64_le(cursor);
    node_limit_           = num_nodes;
    num_witness_accounts_ = num_accounts;
    num_witness_storages_ = num_storages;

    // Pre-size each table to the witness count PLUS a slack for keys created
    // during execution, so created rows append in-place (no realloc → stable
    // View / leaf pointers). Creating an account costs >= ~12.5k gas and a
    // fresh storage slot >= ~20k gas, and total gas <= gas_limit, so
    // gas_limit/10000 is a sound upper bound on created rows — BUT test
    // fixtures set absurd gas_limits (e.g. 1e14), so cap the slack at a value
    // no realistic block reaches (65536 created keys needs >1.6e9 gas of
    // actual work). `append` still fatals if the slack is somehow exceeded,
    // plus a small constant floor for tiny-gas blocks.
    constexpr uint64_t kMaxCreatedSlack = 1u << 16;  // 65536
    const uint64_t slack =
        std::min<uint64_t>(gas_limit / 10000 + 64, kMaxCreatedSlack);
    accounts_.reserve(num_accounts + slack);
    storages_.reserve(num_storages + slack);

    BuildCtx ctx{accounts_, storages_, branch_nodes_, aux_,
                 /*next_state_idx=*/0, /*next_storage_idx=*/0,
                 static_cast<std::size_t>(num_nodes)};
    std::vector<uint8_t> walked;
    walked.reserve(64);  // max trie depth
    root_ = build_node(cursor, ctx, TreeKind::State, walked, /*owning=*/nullptr);

    old_root_ = finalize(
        *result_ptr(root_, branch_nodes_, aux_, accounts_, storages_),
        accounts_, storages_, ValueSet::Original);

    // No bijection check needed: the tables ARE the leaves (built here), so
    // every row appears as exactly one leaf by construction. Soundness comes
    // from old_root_ == the trusted parent anchor (checked by the caller)
    // plus each leaf's verify_path_prefix binding its key to its position.
}

evmc::bytes32 StateRoot::calculate_new_state_root() {
    EvalCtx ctx{accounts_, storages_, branch_nodes_, aux_};
    const auto [root_res, root_ro] = eval_node(root_, ctx, 0);
    (void)root_ro;
    return finalize(*root_res, accounts_, storages_, ValueSet::Current);
}

} // namespace zeg

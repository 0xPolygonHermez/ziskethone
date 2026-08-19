#include "zeg/state_root.hpp"
#include "zeg/zisk_dma.hpp"

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

// The nibbles walked from the root down to the current node. Bounded by the
// 64-nibble key length and pushed/popped once per branch child, so an inline
// stack rather than a `std::vector`.
struct WalkPath {
    static constexpr std::size_t kMax = 64;

    uint8_t buf[kMax];
    uint8_t len = 0;

    // Callers must leave room; `build_branch_node` is the only pusher and
    // checks the depth on entry.
    void push(uint8_t nibble) noexcept { buf[len++] = nibble; }
    void pop() noexcept { --len; }

    const uint8_t* data() const noexcept { return buf; }
    std::size_t    size() const noexcept { return len; }
};

// Two bits per child in the word after Op::Branch. A tagged Empty or Hash child
// carries no opcode word of its own; kTagNode means a whole node follows.
constexpr uint64_t kTagEmpty = 0;
constexpr uint64_t kTagHash  = 1;
constexpr uint64_t kTagNode  = 2;

// `u64 count` then two nibbles per byte, padded to 8 to keep the cursor aligned.
PackedPath read_nibbles(const uint8_t*& cursor) {
    const uint64_t n = read_u64_le(cursor);
    if (n > PackedPath::kMaxNibbles) {
        fatal("state_root: nibble run longer than a 64-nibble key");
    }
    // The witness already carries them packed from a byte boundary, so this is
    // the copy it always was minus the unpacking loop.
    PackedPath out;
    out.assign(cursor, /*first_off=*/0, n);
    cursor += ((n + 1) / 2 + 7) / 8 * 8;
    return out;
}

// Reconstruct keccak(address)/keccak(slot) from the trie path (walked prefix
// + leaf suffix), which must total 64 nibbles = 32 bytes. No preimage needed.
evmc::bytes32 pack_key_hash(const WalkPath& walked, const PackedPath& suffix) {
    if (walked.size() + suffix.size() != 64) {
        fatal("state_root: leaf key path is not 64 nibbles");
    }
    evmc::bytes32 out{};

    // The walk stack is still one nibble per byte (it is pushed and popped a
    // nibble at a time), so it packs here.
    size_t i = 0;
    for (; i < walked.size(); ++i) {
        const uint8_t nib = static_cast<uint8_t>(walked.data()[i] & 0x0f);
        if (i & 1U) out.bytes[i / 2] = static_cast<uint8_t>(out.bytes[i / 2] | nib);
        else        out.bytes[i / 2] = static_cast<uint8_t>(nib << 4);
    }

    // The suffix is already packed. When the walk ended on a byte boundary and
    // the suffix starts on one too, the rest is a copy.
    if ((walked.size() & 1U) == 0 && suffix.off == 0) {
        std::memcpy(out.bytes + walked.size() / 2, suffix.data(), suffix.bytes());
        return out;
    }
    for (size_t k = 0; k < suffix.size(); ++k, ++i) {
        const uint8_t nib = static_cast<uint8_t>(suffix.at(k) & 0x0f);
        if (i & 1U) out.bytes[i / 2] = static_cast<uint8_t>(out.bytes[i / 2] | nib);
        else        out.bytes[i / 2] = static_cast<uint8_t>(nib << 4);
    }
    return out;
}

// ===== pack* (RLP + HP + keccak) ============================================
//
// Each node type has a `build_*_rlp` helper that produces the node's full
// RLP encoding (no hashing) and a thin `pack_*` wrapper that returns its
// keccak256. The split lets the branch assembler apply the Yellow-Paper
// cap function: if the node's RLP is < 32 bytes embed it inline into the
// parent slot, otherwise reference it by its 32-byte hash.

// ===== node encoding ========================================================
//
// Every node's RLP is bounded, so it is built in a stack buffer with the
// enclosing headers written backwards into a reserved gap: no allocation, and no
// byte ever moves. The encoding rules live in zeg/rlp.hpp.

// Space reserved ahead of the payload for the prepended headers and hp item.
constexpr std::size_t kRlpGap = 48;

// Largest inner value a trie leaf can carry. An account is
// [nonce, balance, storageRoot, codeHash] = 9 + 33 + 33 + 33 payload plus a
// 2-byte header = 110; a storage leaf's value is at most 33. 128 leaves
// headroom, and bounds what the witness can ask us to copy — a fork changing
// the account shape needs edits here anyway, since the phantom-account decode
// below reads exactly those four fields.
constexpr std::size_t kMaxLeafValue = 128;
constexpr std::size_t kRlpBuf = kRlpGap + 2 + kMaxLeafValue + 32;

// Worst case for the gap is an account leaf: list header (2) + string header (2)
// + hp item (1 + 33) + the node's own list header (2).
static_assert(kRlpGap >= 2 + 2 + 1 + HpBytes::kMaxNibbles / 2 + 1 + 2,
              "kRlpGap must cover every prepended header");
static_assert(kRlpBuf >= kRlpGap + 2 + kMaxLeafValue,
              "kRlpBuf must cover the widest leaf value");

// Prepend an already-encoded item's bytes (the hex-prefix path) before `start`.
std::size_t prepend_bytes(uint8_t* buf, std::size_t start, const uint8_t* src,
                          std::size_t len) {
    std::memcpy(buf + start - len, src, len);
    return start - len;
}

// [hp, string([nonce, balance, storageRoot, codeHash])] in `buf`.
rlp::BytesView build_account_leaf_rlp_s(
    uint8_t* buf,
    const PackedPath& path_nibbles,
    const Accounts& accounts,
    size_t account_idx,
    const evmc::bytes32& storage_root,
    ValueSet which)
{
    const uint64_t nonce =
        (which == ValueSet::Original) ? accounts.nonce_orig_at(account_idx)
                                      : accounts.nonce_at     (account_idx);
    const evmc::uint256be balance =
        (which == ValueSet::Original) ? accounts.balance_orig_at(account_idx)
                                      : accounts.balance_at     (account_idx);
    const evmc::bytes32 code_hash =
        (which == ValueSet::Original) ? accounts.code_hash_orig_at(account_idx)
                                      : accounts.code_hash_at     (account_idx);

    std::size_t end = kRlpGap;
    end += rlp::write_u64  (buf + end, nonce);
    end += rlp::write_u256 (buf + end, balance);
    end += rlp::write_string(buf + end, storage_root.bytes, sizeof(storage_root.bytes));
    end += rlp::write_string(buf + end, code_hash.bytes, sizeof(code_hash.bytes));

    std::size_t start = rlp::prepend_list  (buf, kRlpGap, end);  // the account
    start = rlp::prepend_string(buf, start, end);                // ... as a byte string

    uint8_t hp_item[36];
    const auto hp = hex_prefix(path_nibbles, /*leaf=*/true);
    const std::size_t hp_len = rlp::write_string(hp_item, hp.data(), hp.size());
    start = prepend_bytes(buf, start, hp_item, hp_len);

    start = rlp::prepend_list(buf, start, end);                  // the leaf node
    return rlp::BytesView{buf + start, end - start};
}

// [hp, string(value)] in `buf`.
rlp::BytesView build_storage_leaf_rlp_s(
    uint8_t* buf,
    const PackedPath& path_nibbles,
    const Storages& storages,
    size_t storage_idx,
    ValueSet which)
{
    const evmc::bytes32 raw =
        (which == ValueSet::Original) ? storages.value_orig_at(storage_idx)
                                      : storages.value_at     (storage_idx);
    evmc::uint256be as_u256;
    std::memcpy(as_u256.bytes, raw.bytes, sizeof(raw.bytes));

    std::size_t end = kRlpGap;
    end += rlp::write_u256(buf + end, as_u256);
    std::size_t start = rlp::prepend_string(buf, kRlpGap, end);

    uint8_t hp_item[36];
    const auto hp = hex_prefix(path_nibbles, /*leaf=*/true);
    const std::size_t hp_len = rlp::write_string(hp_item, hp.data(), hp.size());
    start = prepend_bytes(buf, start, hp_item, hp_len);

    start = rlp::prepend_list(buf, start, end);
    return rlp::BytesView{buf + start, end - start};
}

// [hp, childHash] in `buf`.
rlp::BytesView build_extension_rlp_s(
    uint8_t* buf,
    const PackedPath& ext_nibbles,
    const evmc::bytes32& child_hash)
{
    std::size_t end = kRlpGap;
    end += rlp::write_string(buf + end, child_hash.bytes, sizeof(child_hash.bytes));

    uint8_t hp_item[36];
    const auto hp = hex_prefix(ext_nibbles, /*leaf=*/false);
    const std::size_t hp_len = rlp::write_string(hp_item, hp.data(), hp.size());
    std::size_t start = prepend_bytes(buf, kRlpGap, hp_item, hp_len);

    start = rlp::prepend_list(buf, start, end);
    return rlp::BytesView{buf + start, end - start};
}

evmc::bytes32 pack_account_leaf(
    const PackedPath& path_nibbles,
    const Accounts& accounts,
    size_t account_idx,
    const evmc::bytes32& storage_root,
    ValueSet which)
{
    alignas(8) uint8_t buf[kRlpBuf];
    const auto rlp_bytes = build_account_leaf_rlp_s(buf, path_nibbles, accounts,
                                                    account_idx, storage_root, which);
    return keccak256_bytes32(rlp_bytes.data(), rlp_bytes.size());
}

evmc::bytes32 pack_storage_leaf(
    const PackedPath& path_nibbles,
    const Storages& storages,
    size_t storage_idx,
    ValueSet which)
{
    alignas(8) uint8_t buf[kRlpBuf];
    const auto rlp_bytes = build_storage_leaf_rlp_s(buf, path_nibbles, storages,
                                                    storage_idx, which);
    return keccak256_bytes32(rlp_bytes.data(), rlp_bytes.size());
}

evmc::bytes32 pack_extension(
    const PackedPath& ext_nibbles,
    const evmc::bytes32& child_hash)
{
    alignas(8) uint8_t buf[kRlpBuf];
    const auto rlp_bytes = build_extension_rlp_s(buf, ext_nibbles, child_hash);
    return keccak256_bytes32(rlp_bytes.data(), rlp_bytes.size());
}

// [hp, value] in `buf`. `value_rlp` came from the witness, so its length is
// checked against kMaxLeafValue where it is parsed.
rlp::BytesView build_phantom_leaf_rlp_s(
    uint8_t* buf,
    const PackedPath& path_nibbles,
    const std::vector<uint8_t>& value_rlp)
{
    std::size_t end = kRlpGap;
    end += rlp::write_string(buf + end, value_rlp.data(), value_rlp.size());

    uint8_t hp_item[36];
    const auto hp = hex_prefix(path_nibbles, /*leaf=*/true);
    const std::size_t hp_len = rlp::write_string(hp_item, hp.data(), hp.size());
    std::size_t start = prepend_bytes(buf, kRlpGap, hp_item, hp_len);

    start = rlp::prepend_list(buf, start, end);
    return rlp::BytesView{buf + start, end - start};
}

evmc::bytes32 pack_phantom_leaf(
    const PackedPath& path_nibbles,
    const std::vector<uint8_t>& value_rlp)
{
    alignas(8) uint8_t buf[kRlpBuf];
    const auto rlp_bytes = build_phantom_leaf_rlp_s(buf, path_nibbles, value_rlp);
    return keccak256_bytes32(rlp_bytes.data(), rlp_bytes.size());
}

// A branch stores each child in one slot: by the MPT cap function either the
// child's own RLP inlined (< 32 B) or the RLP string of its hash (33 B). Slot
// bytes go straight into the parent's buffer; staging them per-slot first would
// copy every hash twice, and at RLP's odd offsets both copies are unaligned.
constexpr std::size_t kSlotMax = 33;

// RLP string header for a 32-byte value (0x80 + 32).
constexpr uint8_t kRlpHash32Header = 0xa0;

std::size_t emit_hash_slot(uint8_t* dst, const evmc::bytes32& h) {
    dst[0] = kRlpHash32Header;
    // Constant 32, so this reaches the precompile as one instruction instead of
    // a call into the ziskos thunk. The hottest copy in the guest: 472,786 of
    // them per block, all from reduce_branch.
    zeg::zisk::zisk_xmemcpy<sizeof(h.bytes)>(dst + 1, h.bytes);
    return kSlotMax;
}

// Cap function: inline the node's RLP when short, else reference its hash.
std::size_t emit_capped_slot(uint8_t* dst, rlp::BytesView node_rlp) {
    if (node_rlp.size() >= 32) {
        return emit_hash_slot(dst, keccak256_bytes32(node_rlp.data(), node_rlp.size()));
    }
    zeg::zisk::zisk_memcpy(dst, node_rlp.data(), node_rlp.size());
    return node_rlp.size();
}

// Write this child's slot bytes at `dst`; returns how many bytes were written.
std::size_t emit_child_slot(uint8_t* dst,
                            const NodeR& r,
                            const Accounts& accounts,
                            const Storages& storages,
                            ValueSet which)
{
    // Empty and Hash need no encoding at all and are the vast majority, so
    // answer them before the visit's table dispatch.
    if (std::holds_alternative<EmptyR>(r)) {
        dst[0] = 0x80;
        return 1;
    }
    if (const auto* h = std::get_if<HashR>(&r)) {
        return emit_hash_slot(dst, h->hash);
    }

    return std::visit([&](const auto& x) -> std::size_t {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, EmptyR> || std::is_same_v<T, HashR>) {
            return 0;  // handled above
        } else {
            alignas(8) uint8_t buf[kRlpBuf];
            rlp::BytesView node_rlp;
            if constexpr (std::is_same_v<T, PhantomLeafR>) {
                node_rlp = build_phantom_leaf_rlp_s(buf, x.path_nibbles, x.value_rlp);
            } else if constexpr (std::is_same_v<T, ExtR>) {
                node_rlp = build_extension_rlp_s(buf, x.ext_nibbles, x.hash);
            } else if constexpr (std::is_same_v<T, AccountLeafR>) {
                node_rlp = build_account_leaf_rlp_s(buf, x.path_nibbles, accounts,
                                                    x.account_idx, x.storage_root, which);
            } else {
                node_rlp = build_storage_leaf_rlp_s(buf, x.path_nibbles, storages,
                                                    x.storage_idx, which);
            }
            return emit_capped_slot(dst, node_rlp);
        }
    }, r);
}

// Assemble a branch node from its 16 children, in a stack buffer bounded by 17
// slots plus a header. The payload length is only known at the end, so the
// header is written backwards into a reserved gap and the hash starts wherever
// it landed.
evmc::bytes32 pack_branch(const std::array<const NodeR*, 16>& children,
                          const Accounts& accounts,
                          const Storages& storages,
                          ValueSet which)
{
    constexpr std::size_t kHdrGap = 3;                         // 0xf9 + 2 length bytes
    constexpr std::size_t kBufSize = kHdrGap + 16 * kSlotMax + 1;
    // kHdrGap is only enough while the payload's length fits in two bytes.
    static_assert(16 * kSlotMax + 1 <= 0xffff, "branch payload needs a longer header");

    alignas(8) uint8_t buf[kBufSize];

    std::size_t n = kHdrGap;
    for (const auto* child : children) {
        n += emit_child_slot(buf + n, *child, accounts, storages, which);
    }
    buf[n++] = 0x80;  // the branch's own value slot — always empty

    const std::size_t payload = n - kHdrGap;
    std::size_t start;
    if (payload <= 55) {
        start = kHdrGap - 1;
        buf[start] = static_cast<uint8_t>(0xc0 + payload);
    } else if (payload <= 0xff) {
        start = kHdrGap - 2;
        buf[start]     = 0xf8;
        buf[start + 1] = static_cast<uint8_t>(payload);
    } else {
        start = kHdrGap - 3;
        buf[start]     = 0xf9;
        buf[start + 1] = static_cast<uint8_t>(payload >> 8);
        buf[start + 2] = static_cast<uint8_t>(payload);
    }

    return keccak256_bytes32(buf + start, n - start);
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
            copy.path_nibbles.prepend(nibble);
            return mk_node<AccountLeafR>(std::move(copy));
        }
        if (const auto* leaf = std::get_if<StorageLeafR>(&only)) {
            StorageLeafR copy = *leaf;
            copy.path_nibbles.prepend(nibble);
            return mk_node<StorageLeafR>(std::move(copy));
        }
        if (const auto* leaf = std::get_if<PhantomLeafR>(&only)) {
            PhantomLeafR copy = *leaf;
            copy.path_nibbles.prepend(nibble);
            return mk_node<PhantomLeafR>(std::move(copy));
        }
        if (const auto* h = std::get_if<HashR>(&only)) {
            PackedPath one;          // assign() takes packed bytes; this is a
            one.prepend(nibble);     // loose nibble, so let prepend place it
            return mk_node<ExtR>(std::move(one), h->hash);
        }
        if (const auto* e = std::get_if<ExtR>(&only)) {
            ExtR copy = *e;
            copy.ext_nibbles.prepend(nibble);
            return mk_node<ExtR>(std::move(copy));
        }
    }

    return mk_node<HashR>(pack_branch(children, accounts, storages, which));
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
    // Running lengths of `branch_nodes` and `aux`. std::vector::size() is a
    // pointer difference divided by the element stride, and neither element is
    // power-of-two sized, so GCC lowers each call to a multiply by a reciprocal.
    // Appending one node asked for three of them — the node-limit check reads
    // both, and the returned index reads one again — on the walk's hottest path.
    // 64-bit deliberately: a 32-bit field is a 4-byte access, which ZisK bills
    // at ~141 against ~17 for an aligned 8-byte one, and these two are read
    // and written on the walk's hottest path (once per branch child).
    uint64_t                 aux_n = 0;
    uint64_t                 branch_n = 0;
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
// always_inline, not a hint: a branch calls this 16 times, and GCC otherwise
// leaves a five-case switch out of line, where the call costs more than it.
__attribute__((always_inline))
inline const NodeR* result_ptr(const Child& c,
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

// Construct an aux node in place. Passing a `NodeR` by value would move the
// whole variant twice — into the parameter, then into the vector — and it is as
// large as its widest alternative.
template <class T, class... Args>
uint32_t aux_emplace(BuildCtx& ctx, Args&&... args) {
    if (ctx.branch_n + ctx.aux_n >= ctx.node_limit) {
        fatal("state_root: more nodes than declared (numberOfNodes overflow)");
    }
    ctx.aux.emplace_back(std::in_place_type<T>, std::forward<Args>(args)...);
    return static_cast<uint32_t>(ctx.aux_n++);
}

// Leaf and PhantomLeaf are the heavyweight cases (account decode, an RLP walk, a
// nested storage subtree). Out of line, so the common Hash/ExtensionHash calls
// don't pay a frame sized for them. `noinline` is what survives -O2.
__attribute__((noinline)) Child build_phantom_leaf_node(const uint8_t*& cursor,
                                                        BuildCtx& ctx,
                                                        TreeKind kind,
                                                        WalkPath& walked);
__attribute__((noinline)) Child build_leaf_node(const uint8_t*& cursor,
                                                BuildCtx& ctx,
                                                TreeKind kind,
                                                WalkPath& walked,
                                                const evmc::address* owning_address);
// Branch is outlined for the same reason plus one of its own: its `BranchNode`
// local (16 Childs + a cached NodeR) is what sizes the frame.
__attribute__((noinline)) Child build_branch_node(const uint8_t*& cursor,
                                                  BuildCtx& ctx,
                                                  TreeKind kind,
                                                  WalkPath& walked,
                                                  const evmc::address* owning_address);

// Walk one node from the stream, materialize it (and its subtree) into the
// node array / tables using ORIGINAL values, and return its Child link.
Child build_node(const uint8_t*& cursor,
                 BuildCtx& ctx,
                 TreeKind kind,
                 WalkPath& walked,
                 const evmc::address* owning_address)
{
    const Op op = static_cast<Op>(read_u64_le(cursor));

    switch (op) {
        case Op::Empty:
            return Child{NodeType::Empty, 0};

        case Op::Hash: {
            evmc::bytes32 h;
            zeg::zisk::zisk_xmemcpy<sizeof(h.bytes)>(h.bytes, cursor);
            cursor += sizeof(h.bytes);  // 32 B — already 8-aligned
            return Child{NodeType::Hash, aux_emplace<HashR>(ctx, h)};
        }

        case Op::ExtensionHash: {
            PackedPath ext = read_nibbles(cursor);
            evmc::bytes32 h;
            zeg::zisk::zisk_xmemcpy<sizeof(h.bytes)>(h.bytes, cursor);
            cursor += sizeof(h.bytes);
            return Child{NodeType::ExtensionHash,
                         aux_emplace<ExtR>(ctx, std::move(ext), h)};
        }

        case Op::PhantomLeaf:
            return build_phantom_leaf_node(cursor, ctx, kind, walked);

        case Op::Leaf:
            return build_leaf_node(cursor, ctx, kind, walked, owning_address);

        case Op::Branch:
            return build_branch_node(cursor, ctx, kind, walked, owning_address);
    }

    fatal("state_root: invalid opcode in stream");
}

Child build_branch_node(const uint8_t*& cursor,
                        BuildCtx& ctx,
                        TreeKind kind,
                        WalkPath& walked,
                        const evmc::address* owning_address)
{
    // Depth is witness-controlled — nothing else limits how deeply the stream
    // nests Branch ops — and past 64 nibbles the walk runs off WalkPath's
    // buffer. One check covers all 16 pushes below: each is popped before the
    // next, and the recursive call re-checks for its own level.
    if (walked.size() >= WalkPath::kMax) {
        fatal("state_root: trie path deeper than 64 nibbles");
    }

    // Children are declared up front, two bits each: an Empty child costs no
    // stream bytes and a Hash child only its 32. Together ~92% of the slots, and
    // neither needs the walked path or a recursive frame.
    const uint64_t tags = read_u64_le(cursor);

    BranchNode bn;
    // An Empty child is all-zero bytes (NodeType::Empty == 0, idx == 0), and it
    // is the majority of the 16 slots, so zero the whole array in one op and let
    // the loop below only write the slots that are not empty. Saves a store per
    // empty child, ~9 of the 16 on an average node.
    static_assert(static_cast<int>(NodeType::Empty) == 0,
                  "an all-zero Child must mean Empty");
    zeg::zisk::zisk_xmemset<sizeof(bn.children)>(bn.children.data());
    // `tags` is sixteen 2-bit fields. Shift it along instead of recomputing
    // `tags >> (2*k)` each time, which costs a variable shift per child.
    uint64_t t = tags;
    for (uint8_t k = 0; k < 16; ++k, t >>= 2) {
        switch (t & 0x3u) {
            case kTagEmpty:
                continue;  // already zeroed above
            case kTagHash: {
                evmc::bytes32 h;
                zeg::zisk::zisk_xmemcpy<sizeof(h.bytes)>(h.bytes, cursor);
                cursor += sizeof(h.bytes);  // 32 B — already 8-aligned
                bn.children[k] = Child{NodeType::Hash, aux_emplace<HashR>(ctx, h)};
                continue;
            }
            case kTagNode:
                break;
            default:
                fatal("state_root: invalid branch child tag");
        }
        walked.push(k);
        bn.children[k] = build_node(cursor, ctx, kind, walked, owning_address);
        walked.pop();
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

    if (ctx.branch_n + ctx.aux_n >= ctx.node_limit) {
        fatal("state_root: more nodes than declared (numberOfNodes overflow)");
    }
    ctx.branch_nodes.push_back(std::move(bn));
    return Child{NodeType::Branch, static_cast<uint32_t>(ctx.branch_n++)};
}

Child build_phantom_leaf_node(const uint8_t*& cursor,
                              BuildCtx& ctx,
                              TreeKind kind,
                              WalkPath& walked)
{
    {
            PackedPath path = read_nibbles(cursor);
            const uint64_t value_len = read_u64_le(cursor);
            if (value_len > kMaxLeafValue) {
                fatal("state_root: phantom leaf value exceeds the trie-leaf bound");
            }
            std::vector<uint8_t> value(cursor, cursor + value_len);
            cursor += value_len;
            align_to_u64(cursor, value_len);

            // A preimage-less STATE account (a pre-funded CREATE2 target, or
            // simply a real contract the tracer never touched) has its full
            // field set only in this phantom leaf, never in the Accounts
            // table. Record keccak(addr) -> {nonce, balance, code_hash} so a
            // later resurrection (a CREATE landing here, or merely an
            // EIP-2929 access-warm touch) inherits the REAL fields instead of
            // silently reverting to nonce=0/EMPTY_CODE_HASH, and the new-root
            // pass supersedes the phantom. Account RLP = [nonce, balance,
            // storageRoot, codeHash].
            if (kind == TreeKind::State) {
                const evmc::bytes32 key_hash = pack_key_hash(walked, path);
                rlp::ListIter it(rlp::decode_item(rlp::BytesView{value}).payload);
                const uint64_t nonce = rlp::as_u64(it.next());
                const evmc::uint256be bal = rlp::as_u256(it.next());
                const rlp::Item sroot_item = it.next();  // storageRoot
                evmc::bytes32 sroot{};
                if (sroot_item.payload.size() == sizeof(sroot.bytes))
                    std::memcpy(sroot.bytes, sroot_item.payload.data(), sizeof(sroot.bytes));
                const rlp::Item code_hash_item = it.next();
                evmc::bytes32 code_hash{};
                if (code_hash_item.payload.size() == sizeof(code_hash.bytes)) {
                    std::memcpy(code_hash.bytes, code_hash_item.payload.data(),
                               sizeof(code_hash.bytes));
                } else if (!code_hash_item.payload.empty()) {
                    fatal("state_root: phantom leaf code hash has unexpected length");
                }
                // EMPTY_CODE_HASH itself RLP-encodes as a 32-byte string (RLP
                // byte-strings aren't leading-zero-trimmed like integers), so
                // an empty payload here only happens for the hash of an
                // all-zero 32-byte value, which keccak256("") never is —
                // `code_hash` is already correctly {0}-initialized for that
                // case regardless.
                if (nonce != 0 || bal != evmc::uint256be{} || code_hash != kEmptyCodeHash) {
                    ctx.accounts.record_phantom_account(key_hash, nonce, bal, code_hash, sroot);
                }
            }
            return Child{NodeType::PhantomLeaf,
                         aux_emplace<PhantomLeafR>(ctx, std::move(path),
                                                   std::move(value))};
    }
}

Child build_leaf_node(const uint8_t*& cursor,
                      BuildCtx& ctx,
                      TreeKind kind,
                      WalkPath& walked,
                      const evmc::address* owning_address)
{
    {
            // Payload: suffix nibbles (count u64 + one u64/nibble), then the
            // plaintext key + value. The trie key hash is pack(walked ++
            // suffix); the runtime tables are keyed by the plaintext, bound to
            // the path by keccak(plaintext) == that hash.
            PackedPath suffix = read_nibbles(cursor);

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

                const evmc::bytes32 addr_hash = pack_key_hash(walked, suffix);
                if (keccak256_bytes32(addr.bytes, sizeof(addr.bytes)) != addr_hash) {
                    fatal("state_root: keccak(address) != leaf path hash");
                }

                const size_t idx = ctx.next_state_idx++;
                const size_t a = ctx.accounts.append(addr, nonce, balance, code_hash);
                if (a != idx) fatal("state_root: account append index desync");

                // Build the per-account storage subtree (`addr` is a stable
                // local for the duration of the nested walk).
                WalkPath storage_walked;
                const Child storage_child = build_node(
                    cursor, ctx, TreeKind::Storage, storage_walked, &addr);
                const evmc::bytes32 storage_root = finalize(
                    *result_ptr(storage_child, ctx.branch_nodes, ctx.aux,
                                ctx.accounts, ctx.storages),
                    ctx.accounts, ctx.storages, ValueSet::Original);

                auto nib = path_from_key(addr_hash, walked.size());
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

                const evmc::bytes32 pos_hash = pack_key_hash(walked, suffix);
                if (keccak256_bytes32(position.bytes, sizeof(position.bytes)) != pos_hash) {
                    fatal("state_root: keccak(position) != leaf path hash");
                }

                const size_t idx = ctx.next_storage_idx++;
                const size_t a = ctx.storages.append(*owning_address, position, value);
                if (a != idx) fatal("state_root: storage append index desync");

                auto nib = path_from_key(pos_hash, walked.size());
                ctx.storages.build_value(idx, nib, pos_hash);
                return Child{NodeType::Storage, static_cast<uint32_t>(idx)};
            }
    }
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
            auto nib = path_from_key(ctx.accounts.addr_hash_at(idx), depth);
            const NodeR* r = ctx.accounts.update_value(idx, nib, storage_root);
            const bool read_only = ctx.accounts.fields_unchanged_at(idx) && storage_ro;
            return {r, read_only};
        }

        case NodeType::Storage: {
            const size_t idx = c.idx;
            auto nib = path_from_key(ctx.storages.pos_hash_at(idx), depth);
            const NodeR* r = ctx.storages.update_value(idx, nib);
            return {r, ctx.storages.value_unchanged_at(idx)};
        }

        case NodeType::Branch: {
            BranchNode& bn = ctx.branch_nodes[c.idx];
            std::array<const NodeR*, 16> child_results;
            bool all_ro = true;
            for (uint8_t k = 0; k < 16; ++k) {
                // Most slots are empty or an untouched subtree — the cases this
                // function answers from a table — so resolve them here instead
                // of paying a call. All are read-only, so `all_ro` is unaffected.
                const Child& child = bn.children[k];
                switch (child.type) {
                    case NodeType::Empty:
                        child_results[k] = &empty_result();
                        continue;
                    case NodeType::Hash:
                    case NodeType::ExtensionHash:
                    case NodeType::PhantomLeaf:
                        child_results[k] = &ctx.aux[child.idx];
                        continue;
                    default:
                        break;
                }
                const auto [cr, cro] = eval_node(child, ctx, depth + 1);
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

    // Pre-size each table to the witness count PLUS a slack for rows
    // appended during execution, so they append in-place (no realloc →
    // stable View / leaf pointers). Rows are appended for keys CREATED this
    // block and for witness-absent accounts merely ACCESSED (an empty row,
    // so EIP-2929 warmth can be tracked). The cheapest such event is a cold
    // account access (~2600 gas), and total gas <= gas_limit, so
    // gas_limit/2500 is a sound upper bound — BUT test fixtures set absurd
    // gas_limits (e.g. 1e14), so cap the slack at a value no realistic block
    // reaches. `append` still fatals if the slack is somehow exceeded, plus
    // a small constant floor for tiny-gas blocks.
    constexpr uint64_t kMaxCreatedSlack = 1u << 16;  // 65536
    const uint64_t slack =
        std::min<uint64_t>(gas_limit / 2500 + 64, kMaxCreatedSlack);
    accounts_.reserve(num_accounts + slack);
    storages_.reserve(num_storages + slack);
    aux_.reserve(num_nodes);  // aux nodes are only Hash/ExtensionHash/PhantomLeaf

    BuildCtx ctx{accounts_, storages_, branch_nodes_, aux_,
                 /*next_state_idx=*/0, /*next_storage_idx=*/0,
                 static_cast<std::size_t>(num_nodes)};
    WalkPath walked;
    root_ = build_node(cursor, ctx, TreeKind::State, walked, /*owning=*/nullptr);

    old_root_ = finalize(
        *result_ptr(root_, branch_nodes_, aux_, accounts_, storages_),
        accounts_, storages_, ValueSet::Original);

    // No bijection check needed: the tables ARE the leaves (built here), so
    // every row appears as exactly one leaf by construction. Soundness comes
    // from old_root_ == the trusted parent anchor (checked by the caller)
    // plus each leaf's keccak(key) == path-hash bind (in build_node).
}

// ===== new-root insert (Stage 3) ============================================

uint8_t StateRoot::existing_leaf_nibble(Child leaf, std::size_t d,
                                        std::size_t depth) const {
    switch (leaf.type) {
        case NodeType::Account:
            return nibble_at(accounts_.addr_hash_at(leaf.idx), d);
        case NodeType::Storage:
            return nibble_at(storages_.pos_hash_at(leaf.idx), d);
        case NodeType::PhantomLeaf:
            // The phantom's stored path is relative to where it sits (depth).
            return std::get<PhantomLeafR>(aux_[leaf.idx]).path_nibbles.at(d - depth);
        default:
            fatal("state_root: existing_leaf_nibble on a non-leaf node");
    }
}

Child StateRoot::split_leaf(Child existing, const evmc::bytes32& key_hash,
                            Child leaf, std::size_t depth) {
    // First nibble at which the new key and the existing leaf's key diverge.
    std::size_t d = depth;
    while (true) {
        if (d >= 64) {
            // Identical key. The ONLY sound reason two leaves share a full key
            // is a created account materializing a pre-funded phantom leaf at
            // the same keccak(addr): the created row supersedes the phantom, so
            // return it. Any other identical-key collision is a real bug (a
            // genuine keccak collision or a double-insert) — keep the abort.
            if (existing.type == NodeType::PhantomLeaf) {
                return leaf;
            }
            fatal("state_root: insert collides with an identical key");
        }
        if (nibble_at(key_hash, d) != existing_leaf_nibble(existing, d, depth)) break;
        ++d;
    }
    const uint8_t existing_nib = existing_leaf_nibble(existing, d, depth);

    // A keyless PhantomLeaf carries its path inline, so shorten it to its new
    // (deeper) position d+1. Keyed leaves recompute their path from depth in
    // the eval pass, so they need no surgery here.
    if (existing.type == NodeType::PhantomLeaf) {
        std::get<PhantomLeafR>(aux_[existing.idx]).path_nibbles.drop_front(d + 1 - depth);
    }

    // 2-child branch at depth d holding both leaves.
    BranchNode bd;
    bd.children[nibble_at(key_hash, d)] = leaf;
    bd.children[existing_nib]           = existing;
    branch_nodes_.push_back(std::move(bd));
    Child cur{NodeType::Branch, static_cast<uint32_t>(branch_nodes_.size() - 1)};

    // Single-child branches for the shared nibbles depth..d-1 (reduce_branch
    // folds the chain into an extension at hash time).
    for (std::size_t dd = d; dd > depth; --dd) {
        BranchNode b;
        b.children[nibble_at(key_hash, dd - 1)] = cur;
        branch_nodes_.push_back(std::move(b));
        cur = Child{NodeType::Branch, static_cast<uint32_t>(branch_nodes_.size() - 1)};
    }
    return cur;
}

Child StateRoot::insert_into(Child node, const evmc::bytes32& key_hash,
                             Child leaf, std::size_t depth) {
    switch (node.type) {
        case NodeType::Empty:
            return leaf;
        case NodeType::Branch: {
            const uint8_t nib = nibble_at(key_hash, depth);
            const Child child = branch_nodes_[node.idx].children[nib];  // copy
            const Child newchild = insert_into(child, key_hash, leaf, depth + 1);
            // Re-index after the recursion (which may have grown branch_nodes_).
            branch_nodes_[node.idx].children[nib] = newchild;
            return node;
        }
        case NodeType::Account:
        case NodeType::Storage:
        case NodeType::PhantomLeaf:
            return split_leaf(node, key_hash, leaf, depth);
        case NodeType::Hash:
        case NodeType::ExtensionHash:
            fatal("state_root: insert into an unrevealed (Hash) subtree — "
                  "witness incomplete");
    }
    fatal("state_root: insert_into invalid node type");
}

evmc::bytes32 StateRoot::calculate_new_state_root() {
    // ----- Phase 1: insert keys CREATED during execution -----
    // Rows appended beyond the witness counts are created keys. Splice them
    // into the node array (index-based, so branch_nodes_ may grow freely).

    // Initialise each created account's leaf metadata (appended at run-time
    // via ensure_account, not through build_value). Created rows are keyed by
    // plaintext, so derive the trie key hash here (once, cold).
    for (std::size_t i = num_witness_accounts_; i < accounts_.size(); ++i) {
        const evmc::address& a = accounts_.address_at(i);
        accounts_.set_addr_hash(i, keccak256_bytes32(a.bytes, sizeof(a.bytes)));
        accounts_.set_storage_root_child(i, Child{NodeType::Empty, 0});
    }

    // Insert created storage slots into their owning account's subtree first,
    // so the account leaf's storage root reflects them when evaluated.
    for (std::size_t i = num_witness_storages_; i < storages_.size(); ++i) {
        if (is_zero_value(storages_.value_at(i))) {
            continue;  // a zeroed slot has no trie effect
        }
        const evmc::bytes32& pos = storages_.position_at(i);
        const evmc::bytes32 pos_hash =
            keccak256_bytes32(pos.bytes, sizeof(pos.bytes));
        storages_.set_pos_hash(i, pos_hash);
        const std::size_t acct = accounts_.index_of(storages_.address_at(i));
        const Child new_root = insert_into(
            accounts_.storage_root_child_at(acct), pos_hash,
            Child{NodeType::Storage, static_cast<uint32_t>(i)}, 0);
        accounts_.set_storage_root_child(acct, new_root);
    }

    // Insert created accounts into the state trie. Skip ones that ended empty —
    // UNLESS they superseded a phantom leaf: those are inserted even when empty
    // so insert_into replaces the phantom (updating the branch child type
    // Phantom->Account, so eval re-hashes instead of reusing the cached phantom
    // hash). ensure_account seeded the row's ORIGINAL from the phantom's fields,
    // so eval sees original != current and re-hashes correctly.
    for (std::size_t i = num_witness_accounts_; i < accounts_.size(); ++i) {
        const bool empty = is_empty_account(accounts_.nonce_at(i),
                                            accounts_.balance_at(i),
                                            accounts_.code_hash_at(i));
        const evmc::bytes32& ah = accounts_.addr_hash_at(i);
        const Accounts::PhantomAccount* ph = accounts_.phantom_account(ah);
        const bool superseded_phantom = ph != nullptr;
        if (superseded_phantom && ph->storage_root != kEmptyTrieRoot) {
            // A resurrected phantom is rebuilt above with storage_root_child =
            // Empty (Phase-1 loop), which the account leaf will hash as an
            // empty storage root. That is only correct when the phantom's
            // block-start storage was itself empty. A non-empty storage root
            // here means the row lost the account's real storage — and we
            // cannot rebuild it (a preimage-less phantom ships no storage
            // subtree in the witness). This never arises from a faithful reth
            // witness: any account whose storage the block touches has its
            // storage nodes revealed, so it arrives as a real Op::Leaf, not a
            // phantom; and a phantom that is merely balance-credited or
            // access-warmed has its storage untouched. Refuse rather than emit
            // a silently-wrong root.
            fatal("state_root: resurrected phantom has non-empty storage "
                  "(witness lacks its storage subtree)");
        }
        if (empty && !superseded_phantom) {
            continue;
        }
        root_ = insert_into(root_, ah,
                            Child{NodeType::Account, static_cast<uint32_t>(i)}, 0);
    }

    // ----- Phase 2: evaluate the augmented node array against current values.
    EvalCtx ctx{accounts_, storages_, branch_nodes_, aux_};
    const auto [root_res, root_ro] = eval_node(root_, ctx, 0);
    (void)root_ro;
    return finalize(*root_res, accounts_, storages_, ValueSet::Current);
}

} // namespace zeg

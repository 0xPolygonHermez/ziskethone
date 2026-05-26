#include "zeg/mpt.hpp"

#include <algorithm>
#include <span>

#include "zeg/hex_prefix.hpp"
#include "zeg/keccak.hpp"
#include "zeg/rlp.hpp"

namespace zeg {

namespace {

using rlp::BytesView;

// One entry as the recursive builder sees it: the path is the key
// expanded to nibbles (high then low) and the value is unchanged.
struct PathEntry {
    std::vector<uint8_t> path;
    const std::vector<uint8_t>* value;  // pointer into the caller's storage
};

// Expand `key` into nibbles, high-nibble-first.
std::vector<uint8_t> to_nibbles(const std::vector<uint8_t>& key) {
    std::vector<uint8_t> n;
    n.reserve(key.size() * 2);
    for (uint8_t b : key) {
        n.push_back(static_cast<uint8_t>(b >> 4));
        n.push_back(static_cast<uint8_t>(b & 0x0f));
    }
    return n;
}

// Encode a child reference per the Yellow Paper:
//   * If the child node's RLP encoding is < 32 bytes → inline it.
//   * Otherwise → RLP-encode keccak256(node_rlp) as a 32-byte string.
rlp::Bytes node_ref(const rlp::Bytes& node_rlp) {
    if (node_rlp.size() < 32) {
        return node_rlp;
    }
    const auto h = keccak256_bytes32(node_rlp.data(), node_rlp.size());
    return rlp::encode(BytesView{h.bytes, sizeof(h.bytes)});
}

// Forward decl.
rlp::Bytes build_node(std::span<const PathEntry> entries, size_t depth);

// One non-empty bucket of the branch's 16 children. Recurses with
// depth + 1 so the consumed nibble drops out of the subtree paths.
rlp::Bytes build_branch_child(std::span<const PathEntry> bucket, size_t depth) {
    return node_ref(build_node(bucket, depth + 1));
}

rlp::Bytes build_node(std::span<const PathEntry> entries, size_t depth) {
    // Single entry → leaf node: [HP(path[depth..], leaf=true), value].
    if (entries.size() == 1) {
        const auto& e = entries[0];
        const auto rest = std::span<const uint8_t>{e.path}.subspan(depth);
        const auto hp = hex_prefix(rest, /*leaf=*/true);
        return rlp::encode_list({
            BytesView{rlp::encode(BytesView{hp.data(), hp.size()})},
            BytesView{rlp::encode(BytesView{e.value->data(), e.value->size()})},
        });
    }

    // Find the longest common prefix beyond `depth`. We know all
    // entries are sorted, so it's enough to compare the first and
    // last entries — every entry in between shares any nibble that
    // those two share.
    const auto& first = entries.front();
    const auto& last  = entries.back();
    size_t common = depth;
    while (common < first.path.size() && common < last.path.size()
           && first.path[common] == last.path[common]) {
        ++common;
    }

    // Common prefix beyond `depth` → extension wrapping a deeper node.
    if (common > depth) {
        const auto ext = std::span<const uint8_t>{first.path}.subspan(
            depth, common - depth);
        const auto hp = hex_prefix(ext, /*leaf=*/false);
        const auto child_rlp = build_node(entries, common);
        return rlp::encode_list({
            BytesView{rlp::encode(BytesView{hp.data(), hp.size()})},
            BytesView{node_ref(child_rlp)},
        });
    }

    // Branch node: 16 nibble buckets + an optional value at this
    // level (for any entry whose path ends exactly at `depth`).
    // Default value slot is the empty-string RLP byte (0x80).
    static const rlp::Bytes kEmpty{0x80};
    std::array<rlp::Bytes, 16> child_refs;
    for (auto& r : child_refs) r = kEmpty;
    rlp::Bytes value_slot = kEmpty;

    // Walk the (sorted) entries; each contiguous run with the same
    // nibble at `depth` is one bucket.
    size_t i = 0;
    while (i < entries.size()) {
        if (entries[i].path.size() == depth) {
            // Key terminates exactly here → put the value in the
            // branch's value slot. (There can be at most one such
            // entry given the keys are unique.)
            value_slot = rlp::encode(BytesView{entries[i].value->data(),
                                                entries[i].value->size()});
            ++i;
            continue;
        }
        const uint8_t nib = entries[i].path[depth];
        size_t j = i + 1;
        while (j < entries.size()
               && entries[j].path.size() > depth
               && entries[j].path[depth] == nib) {
            ++j;
        }
        child_refs[nib] = build_branch_child(entries.subspan(i, j - i), depth);
        i = j;
    }

    return rlp::encode_list({
        BytesView{child_refs[0]},  BytesView{child_refs[1]},
        BytesView{child_refs[2]},  BytesView{child_refs[3]},
        BytesView{child_refs[4]},  BytesView{child_refs[5]},
        BytesView{child_refs[6]},  BytesView{child_refs[7]},
        BytesView{child_refs[8]},  BytesView{child_refs[9]},
        BytesView{child_refs[10]}, BytesView{child_refs[11]},
        BytesView{child_refs[12]}, BytesView{child_refs[13]},
        BytesView{child_refs[14]}, BytesView{child_refs[15]},
        BytesView{value_slot},
    });
}

} // namespace

void MerklePatriciaTrie::insert(std::vector<uint8_t> key,
                                std::vector<uint8_t> value) {
    entries_.emplace_back(std::move(key), std::move(value));
}

evmc::bytes32 MerklePatriciaTrie::root_hash() const {
    if (entries_.empty()) {
        // Empty-trie root: keccak256(rlp("")) = keccak256(0x80).
        const uint8_t empty_rlp = 0x80;
        return keccak256_bytes32(&empty_rlp, 1);
    }

    // Materialize sorted-by-nibble-path entries.
    std::vector<PathEntry> pe;
    pe.reserve(entries_.size());
    for (const auto& [k, v] : entries_) {
        pe.push_back(PathEntry{to_nibbles(k), &v});
    }
    std::sort(pe.begin(), pe.end(),
              [](const PathEntry& a, const PathEntry& b) {
                  return a.path < b.path;
              });

    const auto root_rlp = build_node(std::span<const PathEntry>{pe}, 0);
    return keccak256_bytes32(root_rlp.data(), root_rlp.size());
}

} // namespace zeg

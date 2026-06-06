// Merkle Patricia Trie root computation for the ZisK Ethereum guest.
//
// `StateRoot` reconstructs the world-state root in two passes. The first
// (the constructor) reads the original (block-start) values the leaf
// opcodes carry, **builds** the Accounts/Storages tables (one row per
// keyed leaf), produces the pre-execution root, and **materializes an
// explicit node array** — `branch_nodes_` (16 typed child links + the
// branch's computed result) plus the per-leaf cached result the tables
// own. The second pass (`calculate_new_state_root`) walks that node array
// (not the stream) against the current values, reusing a node's cached
// result whenever it is read-only and re-hashing only what changed. The
// same machinery handles the state trie and per-account storage tries (an
// account row links to its storage-subtree root node).
//
// The StateRoot section begins with three u64 counts — numberOfNodes,
// numberOfAccounts, numberOfStorages — read by the constructor to pre-size
// the tables (and bound the node array). Because the tables are built
// here, the constructor MUST run before the EVM executes the block.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <evmc/evmc.hpp>

#include "zeg/trie_node.hpp"

namespace zeg {

class Accounts;
class Storages;

class StateRoot {
public:
    // ----- public API -------------------------------------------------------

    // Reads the section's three header counts, pre-sizes the (empty)
    // `accounts` / `storages` tables (witness count + a gas-bounded slack
    // for keys CREATED during execution), then walks the stream once with
    // the original (block-start) values the leaf opcodes carry: it APPENDS
    // one row per keyed leaf, materializes the node array, computes the old
    // state root, and caches every node's result. `cursor` is advanced past
    // the counts and every byte consumed by the walk. The tables must be
    // empty on entry and are owned by the caller (the EVM mutates them — and
    // may append created rows into the slack — after this returns).
    // `gas_limit` (from the verified consensus header) bounds how many keys
    // the block can create, sizing the slack.
    StateRoot(const uint8_t*& cursor,
              Accounts& accounts,
              Storages& storages,
              uint64_t gas_limit);

    // O(1) — the value computed in the constructor.
    const evmc::bytes32& old_state_root() const noexcept { return old_root_; }

    // Walks the node array built in the constructor against the current
    // (post-execution) values. Read-only-ness is derived dynamically (a
    // leaf is read-only iff its original == current value; a node iff all
    // its children are), and a read-only node reuses its cached old-root
    // result instead of re-hashing.
    evmc::bytes32 calculate_new_state_root();

private:
    // ----- new-root insert helpers (Stage 3) --------------------------------
    //
    // Splice a created key's leaf into the node array along `key_hash`.
    // `insert_into` returns the (possibly new) root of the subtree it was
    // given: it places the leaf at an `Empty` slot, descends a `Branch`, or
    // `split`s a colliding sibling leaf into a fresh branch chain. It fatals
    // on a `Hash`/`ExtensionHash` (insertion into an unrevealed subtree —
    // the witness must reveal the insertion neighbourhood).
    Child insert_into(Child node, const evmc::bytes32& key_hash,
                      Child leaf, std::size_t depth);
    Child split_leaf(Child existing, const evmc::bytes32& key_hash,
                     Child leaf, std::size_t depth);
    // The existing leaf's nibble at absolute depth `d` (its key sits at
    // `depth`). Uses addr_hash/pos_hash for keyed leaves, the stored path
    // for a keyless PhantomLeaf.
    uint8_t existing_leaf_nibble(Child leaf, std::size_t d, std::size_t depth) const;

    Accounts& accounts_;
    Storages& storages_;
    // Declared node-count ceiling (header `numberOfNodes`); the build pass
    // fatals if `branch_nodes_` + `aux_` would exceed it.
    uint64_t        node_limit_ = 0;
    // Witness leaf counts (header). Rows appended beyond these during
    // execution are keys CREATED this block; the new-root pass inserts them.
    uint64_t        num_witness_accounts_ = 0;
    uint64_t        num_witness_storages_ = 0;
    evmc::bytes32   old_root_{};

    // The materialized node array. `branch_nodes_` holds every 16-ary
    // branch (its child links + computed result); `aux_` holds the fixed,
    // always-read-only results of Hash / ExtensionHash / PhantomLeaf nodes.
    // Leaf results live on the Accounts/Storages rows. `root_` is the tree
    // root.
    std::vector<BranchNode> branch_nodes_;
    std::vector<NodeR>      aux_;
    Child                   root_{};
};

} // namespace zeg

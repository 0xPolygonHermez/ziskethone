// Merkle Patricia Trie root computation for the ZisK Ethereum guest.
//
// `StateRoot` walks the stream-encoded trie twice. The first walk
// (driven from the constructor) reads the original (block-start) values
// the leaf opcodes carry, **builds** the Accounts/Storages tables as it
// goes (one row per keyed leaf), produces the pre-execution root, and
// records every node's result in `cache_` (post-order). The second walk
// (calculate_new_state_root) reads the current values (originals + EVM
// modifications) and reuses the cached result for any read-only node so
// unchanged regions don't get re-hashed. The same recursive routine
// handles the state trie and per-account storage tries (a state-trie
// leaf carries the storage subtree inline).
//
// The StateRoot section begins with three u64 counts — numberOfNodes,
// numberOfAccounts, numberOfStorages — read by the constructor to
// pre-size the per-node cache and the two tables (and to reject a stream
// that overflows them). Because the tables are built here, the
// constructor MUST run before the EVM executes the block.

#pragma once

#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg {

class Accounts;
class Storages;

class StateRoot {
public:
    // ----- internal node-result types ---------------------------------------
    //
    // These are exposed here only because StateRoot stores a
    // `std::vector<CacheEntry>` as a member, and the compiler needs the
    // complete type of CacheEntry (and transitively NodeR) to lay out
    // the class. They are implementation detail of state_root.cpp —
    // treat as opaque from outside the implementation TU.

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
    /// Fallback leaf the prover carried inline via `Op::PhantomLeaf`.
    /// Used only when Reth's `witness.keys` omits the keccak preimage
    /// of a sibling leaf the chain trie's witness contains — we still
    /// need to re-position it under structural splits, but can't
    /// reference it by Accounts/Storages idx because we don't know
    /// its address/slot. `value_rlp` is the leaf's raw inner value
    /// bytes (account RLP for state trie, u256 RLP for storage);
    /// cpp-guest wraps them in HP + RLP at pack time.
    ///
    /// The common path (witness leaves whose preimage IS exposed)
    /// goes through `AccountLeafR`/`StorageLeafR` via `Op::Leaf` (its
    /// table index derived from the walk counter) after
    /// `enrich::enrich_state_leaves_from_witness` etc. populate our
    /// prestate. This variant exists for the residual gap only.
    struct PhantomLeafR {
        std::vector<uint8_t> path_nibbles;
        std::vector<uint8_t> value_rlp;
    };

    using NodeR = std::variant<EmptyR, HashR, ExtR, AccountLeafR, StorageLeafR, PhantomLeafR>;

    // ----- public API -------------------------------------------------------

    // Reads the section's three header counts, pre-sizes the cache and
    // the (empty) `accounts` / `storages` tables, then walks the stream
    // once with the original (block-start) values the leaf opcodes carry:
    // it APPENDS one row per keyed leaf into the tables, computes the old
    // state root, and records EVERY node's result in `cache_` (post-order).
    // `cursor` is advanced past the counts and every byte consumed by the
    // walk. The tables must be empty on entry and are owned by the caller
    // (the EVM mutates them after this constructor returns).
    StateRoot(const uint8_t*& cursor,
              Accounts& accounts,
              Storages& storages);

    // O(1) — the value computed in the constructor.
    const evmc::bytes32& old_state_root() const noexcept { return old_root_; }

    // Re-walks from the remembered start cursor with the current
    // (post-execution) values. Read-only-ness is derived dynamically (a
    // leaf is read-only iff its original == current value; a node iff all
    // its children are), and the cached old-root result is reused for any
    // read-only node instead of re-hashing it.
    evmc::bytes32 calculate_new_state_root();

private:
    Accounts& accounts_;
    Storages& storages_;
    const uint8_t*  start_cursor_ = nullptr;
    // Declared node count (header); the old-root pass fatals if it would
    // push more than this into `cache_`.
    uint64_t        node_limit_ = 0;
    evmc::bytes32   old_root_{};
    // Per-node result cache filled by the old-root pass in post-order;
    // the new-root pass reads it back in the same order, reusing the
    // result for read-only nodes.
    std::vector<NodeR> cache_;
    std::size_t cache_read_pos_ = 0;
};

} // namespace zeg

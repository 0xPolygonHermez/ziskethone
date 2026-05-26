// MerklePatriciaTrie — build-once / hash-once Ethereum MPT.
//
// Designed for trie types whose contents are known upfront and never
// mutated again (transactions trie, receipts trie, withdrawals trie,
// EIP-7685 requests trie). Inserts are O(1) accumulation; the actual
// trie is materialized on the first call to `root_hash()`.
//
// For the persistent world-state trie we have `zeg::StateRoot`, which
// walks a prover-supplied hint structure instead of building from
// scratch — that's a different problem and a different class.

#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg {

class MerklePatriciaTrie {
public:
    // Accumulate a (key, value) pair. Both are owned copies. Multiple
    // inserts with the same key are not deduplicated — callers should
    // not insert duplicates for the tries this class is used to build.
    void insert(std::vector<uint8_t> key, std::vector<uint8_t> value);

    // Canonical 32-byte trie root: keccak256(rlp(root_node)). For an
    // empty trie, returns keccak256(0x80) (= 0x56e81f17…b421, the
    // well-known empty-trie root). Pure / `const`-friendly: doesn't
    // mutate any accumulated state.
    evmc::bytes32 root_hash() const;

    size_t size() const noexcept { return entries_.size(); }

private:
    std::vector<std::pair<std::vector<uint8_t>,
                          std::vector<uint8_t>>> entries_;
};

} // namespace zeg

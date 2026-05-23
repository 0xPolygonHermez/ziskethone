// Merkle Patricia Trie root computation for the ZisK Ethereum guest.
//
// Reads a stream-encoded representation of the trie (see Op in the .cpp)
// and returns the root hash. The stream encoding lets the prover skip
// over subtrees by sending only their precomputed root hash, and lets
// the verifier defer per-leaf hashing until a sibling forces it. The
// same recursive routine handles the state trie and per-account storage
// tries (a state-trie leaf carries the storage subtree inline).

#pragma once

#include <cstdint>

#include <evmc/evmc.hpp>

namespace zeg {

class Accounts;
class Storages;

// Walk the stream-encoded trie starting at `cursor` and return its root
// hash. `cursor` is advanced past every byte consumed. `accounts` and
// `storages` supply the per-leaf payloads (addresses / positions /
// account fields / slot values); whether a leaf hash is computed from
// the "original" or "current" values is decided by the dirty-aware
// accessors on those classes, so the same function computes both the
// pre-execution and post-execution roots.
evmc::bytes32 calculate_state_root(
    const uint8_t*& cursor,
    const Accounts& accounts,
    const Storages& storages);

} // namespace zeg

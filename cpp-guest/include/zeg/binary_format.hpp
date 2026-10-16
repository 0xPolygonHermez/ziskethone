// Binary input format consumed by the ZisK Ethereum block guest.
// See ../../BINARY_FORMAT.md for the authoritative specification.
//
// All structs are little-endian and byte-packed so the file can be accessed
// via direct pointer cast (zero-parse on the guest side).

#pragma once

#include <cstdint>

namespace zeg {

constexpr uint32_t kMagic   = 0x3047455Au; // "ZEG0" little-endian
// Format version, stored in the 4 bytes immediately after the magic.
// v12: every key the block loads is a StateRoot leaf — one that doesn't
//      exist is an empty leaf where it would sit (its absence proven by the
//      parent-root check), so the guest halts on any other load and appends
//      no rows at run time. Sorted-order links replace the BalHint section:
//      the header gains first_sorted_account (u64), a state Leaf gains
//      next_sorted_account + first_sorted_storage (u64 each), a storage Leaf
//      next_sorted_storage (u64).
// v11: EIP-7928 — block_access_list_hash leaves ConsensusInfo (prefix
//      408 → 376 B, slot_number moves to 368; the guest builds the BAL and
//      computes the hash), and a trailing BalHint section after StateRoot
//      lists the BAL's addresses and slots in order.
// v10: Amsterdam header fields — ConsensusInfo prefix 368 → 408 B
//      (block_access_list_hash at 368, slot_number at 400) and PreviousBlocks
//      records 728 → 768 B (same two fields at 728 / 760), so the guest can
//      hash 23-field Amsterdam headers.
// v9: compact StateRoot — a branch tags its 16 children in one word (a tagged
//     Empty child costs no bytes, a Hash child 32) and nibbles pack two per
//     byte. ~22% smaller witness.
// v7: stateless StateRoot — each `Op::Leaf` carries its key-suffix nibbles
//     (the guest packs walked ++ suffix into the trie key hash, no preimage)
//     plus the plaintext key + block-start values. The guest keys its runtime
//     tables by plaintext and binds keccak(plaintext) == the path hash.
// v6: no secp256k1 pubkey hints — the per-tx 64 B sender pubkey and the
//     Type-4 per-authorization 64 B pubkeys are removed from the Transactions
//     section; the guest recovers every signer itself via ecrecover
//     (fp_sqrt-fcall accelerated on ZisK).
// v5: ConsensusInfo fixed prefix grew 8 B — adds blob_base_fee_update_fraction
//     (u64-le at offset 344), so the guest charges blob gas with the block's
//     actual BLOB_BASE_FEE_UPDATE_FRACTION instead of a hardcoded constant.
// v4: StateRoot trie hints are now WITNESS-ONLY — the encoder transcribes
//     the pre-state MPT straight from debug_executionWitness and no longer
//     pre-emits leaves for keys created during the block; the guest inserts
//     them into the node array during the new-root pass. Byte layout is
//     unchanged from v3, but a v4 stream requires the inserting guest.
// v3: dropped the Accounts/Storages sections — the StateRoot section now
//     starts with three u64 counts (numberOfNodes, numberOfAccounts,
//     numberOfStorages) and each `Op::Leaf` carries its key + block-start
//     values, so the guest builds both tables dynamically during the
//     old-root walk (which now runs before execution).
// v2: single `Op::Branch` opcode (no NodeR/NodeRW); `is_read_only` dropped
//     from the Accounts (now 128 B) and Storages (now 88 B) records — the
//     guest derives read-only-ness dynamically (original == current).
// v1: StateRoot `Op::Leaf` carries no index; keccak-sorted tables.
// The guest rejects any version != kVersion.
constexpr uint32_t kVersion = 13; // v13: 16-byte hash seed at offset [8,24),
                                  // right after the magic+version prefix, so the
                                  // cursor to the first section starts at 24. The
                                  // guest uses it only to seed its internal
                                  // hash-map bucket selection (defeats forced
                                  // O(n^2) account/storage lookups); it never
                                  // affects the public output.
                                  // v8: ConsensusInfo prefix +8 B —
                                  // adds target_blob_gas_per_block (u64-le
                                  // at offset 352) so the guest can
                                  // independently re-derive and validate
                                  // excess_blob_gas (EIP-4844) instead of
                                  // trusting the header's claimed value.
                                  // v7 leaf: suffix nibbles + plaintext key + value

enum class SectionKind : uint32_t {
    ParentHeader      = 1,
    CurrentHeader     = 2,
    Transactions      = 3,
    Withdrawals       = 4,
    StateTrieNodes    = 5,
    StorageTrieNodes  = 6,
    Bytecodes         = 7,
    AncestorHeaders   = 8,
};

#pragma pack(push, 1)

struct FileHeader {
    uint8_t  magic[4];     // "ZEG0"
    uint32_t version;
    uint32_t section_count;
    uint32_t flags;
    uint64_t chain_id;
    uint64_t block_number;
};
static_assert(sizeof(FileHeader) == 32, "FileHeader must be 32 bytes");

struct SectionEntry {
    uint32_t kind;
    uint32_t reserved;
    uint32_t offset;
    uint32_t length;
};
static_assert(sizeof(SectionEntry) == 16, "SectionEntry must be 16 bytes");

#pragma pack(pop)

} // namespace zeg

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
// v9: contract diffs — a contract record carries a kind word, so a
//     near-duplicate bytecode is stored as a diff against an earlier record
//     instead of in full. ~27% smaller witness on pool-sweeping blocks.
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
constexpr uint32_t kVersion = 9;  // v8: ConsensusInfo prefix +8 B —
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

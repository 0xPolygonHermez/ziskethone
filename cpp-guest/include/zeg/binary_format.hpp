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
constexpr uint32_t kVersion = 3;

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

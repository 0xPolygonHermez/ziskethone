// Binary input format consumed by the ZisK Ethereum block guest.
// See ../../BINARY_FORMAT.md for the authoritative specification.
//
// All structs are little-endian and byte-packed so the file can be accessed
// via direct pointer cast (zero-parse on the guest side).

#pragma once

#include <cstdint>

namespace zeb {

constexpr uint32_t kMagic   = 0x3042455Au; // "ZEB0" little-endian
constexpr uint32_t kVersion = 0;

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
    uint8_t  magic[4];     // "ZEB0"
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

} // namespace zeb

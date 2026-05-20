// Host-side sanity reader for the ZisK Ethereum guest input file.
//
// This is NOT the actual ZisK guest program. It is a development tool that
// validates the binary container produced by `rust-input-gen` can be parsed
// with the zero-copy layout described in `BINARY_FORMAT.md`.
//
// The real guest's `main()` will:
//   1. Map / read the input file from the ZisK private-input channel.
//   2. RLP-decode the parent and current headers.
//   3. Statelessly re-execute transactions against the witness trie.
//   4. Commit `previousBlockHash` and `nextBlockHash` as public outputs.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

#include "zeb/binary_format.hpp"

namespace {

const char* kind_name(uint32_t k) {
    using zeb::SectionKind;
    switch (static_cast<SectionKind>(k)) {
        case SectionKind::ParentHeader:     return "PARENT_HEADER";
        case SectionKind::CurrentHeader:    return "CURRENT_HEADER";
        case SectionKind::Transactions:     return "TRANSACTIONS";
        case SectionKind::Withdrawals:      return "WITHDRAWALS";
        case SectionKind::StateTrieNodes:   return "STATE_TRIE_NODES";
        case SectionKind::StorageTrieNodes: return "STORAGE_TRIE_NODES";
        case SectionKind::Bytecodes:        return "BYTECODES";
        case SectionKind::AncestorHeaders:  return "ANCESTOR_HEADERS";
        default: return "UNKNOWN";
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <input.bin>\n", argv[0]);
        return 2;
    }

    std::ifstream in(argv[1], std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "failed to open %s\n", argv[1]);
        return 1;
    }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    if (buf.size() < sizeof(zeb::FileHeader)) {
        std::fprintf(stderr, "file too small\n");
        return 1;
    }

    const auto* hdr = reinterpret_cast<const zeb::FileHeader*>(buf.data());
    if (std::memcmp(hdr->magic, "ZEB0", 4) != 0) {
        std::fprintf(stderr, "bad magic\n");
        return 1;
    }
    if (hdr->version != zeb::kVersion) {
        std::fprintf(stderr, "unsupported version %u\n", hdr->version);
        return 1;
    }

    std::printf("magic=ZEB0 version=%u chain_id=%llu block=%llu sections=%u\n",
                hdr->version,
                static_cast<unsigned long long>(hdr->chain_id),
                static_cast<unsigned long long>(hdr->block_number),
                hdr->section_count);

    const auto* table = reinterpret_cast<const zeb::SectionEntry*>(
        buf.data() + sizeof(zeb::FileHeader));
    for (uint32_t i = 0; i < hdr->section_count; ++i) {
        const auto& e = table[i];
        std::printf("  [%u] kind=%-18s offset=%u length=%u\n",
                    i, kind_name(e.kind), e.offset, e.length);
        if (e.offset + e.length > buf.size()) {
            std::fprintf(stderr, "section %u out of bounds\n", i);
            return 1;
        }
    }
    return 0;
}

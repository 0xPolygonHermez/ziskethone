#include "zeg/contracts.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>

#include <evmone_precompiles/keccak.hpp>

#include "zeg/fatal.hpp"
#include "zeg/hash_reserve.hpp"
#include "zeg/stream.hpp"

namespace zeg {

Contracts::Contracts(const uint8_t*& cursor) {
    const uint64_t count = read_u64_le(cursor);
    // Each contract needs at least its 8-byte size prefix, so a count beyond
    // that many remaining bytes is a malformed/oversized input — reject before
    // the huge reserve and the loop (bounds checks, see zeg/stream.hpp).
    if (count > stream_remaining(cursor) / 8) {
        fatal("Contracts: count exceeds input size");
    }
    contracts_.reserve(count);
    hash_reserve_empty(index_, count);  // not .reserve(): see zeg/hash_reserve.hpp
    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t size = read_u64_le(cursor);
        const uint8_t* code = cursor;
        advance_checked(cursor, size);
        align_to_u64(cursor, size);

        const auto digest = ethash::keccak256(code, size);
        evmc::bytes32 hash;
        std::memcpy(hash.bytes, digest.bytes, sizeof(hash.bytes));

        contracts_.push_back(Contract{hash, code, size});
        index_.emplace(hash, contracts_.size() - 1);
    }
}

size_t Contracts::index_of(const evmc::bytes32& hash) const {
    const auto it = index_.find(hash);
    if (it == index_.end()) {
        std::fprintf(stderr, "DBG missing code hash 0x");
        for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", hash.bytes[i]);
        std::fprintf(stderr, "\n");
        fatal("Contracts::index_of: code hash not present in the table");
    }
#if !defined(ZEG_ZISK)
    // DEBUG (host): report each code the block uses, so a host can drop the
    // unused ones from the input (reth-zisk-exex trims its BAL-built input).
    static const bool dump_used = std::getenv("ZEG_DUMP_USED") != nullptr;
    if (dump_used) {
        static std::set<evmc::bytes32> seen;
        if (seen.insert(hash).second) {
            std::fprintf(stderr, "USED code 0x");
            for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", hash.bytes[i]);
            std::fprintf(stderr, "\n");
        }
    }
#endif
    return it->second;
}


} // namespace zeg

#include "zeg/contracts.hpp"

#include <cstring>

#include <evmone_precompiles/keccak.hpp>

#include "zeg/fatal.hpp"
#include "zeg/stream.hpp"

namespace zeg {

Contracts::Contracts(uint64_t count, const uint8_t*& cursor) {
    contracts_.reserve(count);
    index_.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t size = read_u64_le(cursor);
        const uint8_t* code = cursor;
        cursor += size;
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
        fatal("Contracts::index_of: code hash not present in the table");
    }
    return it->second;
}

} // namespace zeg

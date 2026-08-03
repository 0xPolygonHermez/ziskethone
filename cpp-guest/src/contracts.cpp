#include "zeg/contracts.hpp"

#include <cstdio>
#include <cstring>

#include <evmone_precompiles/keccak.hpp>

#include "zeg/fatal.hpp"
#include "zeg/hash_reserve.hpp"
#include "zeg/stream.hpp"

namespace zeg {

namespace {

// A literal record carries its bytecode; a diff carries an earlier record's
// index plus the runs that differ from it — how immutable-variant clones avoid
// a second full copy of a 22 KB pool.
constexpr uint64_t kLiteral = 0;
constexpr uint64_t kDiff    = 1;

}  // namespace

Contracts::Contracts(const uint8_t*& cursor) {
    const uint64_t count = read_u64_le(cursor);
    contracts_.reserve(count);
    dynamic_codes_.reserve(count);  // reconstructed clones land here
    hash_reserve_empty(index_, count);  // not .reserve(): see zeg/hash_reserve.hpp
    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t size = read_u64_le(cursor);
        const uint64_t kind = read_u64_le(cursor);
        const uint8_t* code = nullptr;

        if (kind == kLiteral) {
            code = cursor;
            cursor += size;
            align_to_u64(cursor, size);
        } else if (kind == kDiff) {
            // Rebuild from an earlier record. Every length here is
            // witness-controlled, so each is checked — and a wrong
            // reconstruction cannot pass unnoticed anyway, since the keccak
            // below then fails to match what the block asks for.
            const uint64_t tmpl = read_u64_le(cursor);
            if (tmpl >= i) {
                fatal("contracts: diff template is not an earlier record");
            }
            const Contract& base = contracts_[tmpl];
            if (base.code_size != size) {
                fatal("contracts: diff template size mismatch");
            }
            const uint64_t runs = read_u64_le(cursor);
            if (runs > size) {  // a run needs at least one byte
                fatal("contracts: diff declares more runs than bytes");
            }
            dynamic_codes_.emplace_back(base.code, base.code + size);
            uint8_t* dst = dynamic_codes_.back().data();

            const uint8_t* desc = cursor;                // runs x {u32 off, u32 len}
            const uint8_t* payload = cursor + runs * 8;  // the differing bytes
            uint64_t total = 0;
            for (uint64_t r = 0; r < runs; ++r) {
                uint32_t off;
                uint32_t len;
                std::memcpy(&off, desc + r * 8, sizeof(off));
                std::memcpy(&len, desc + r * 8 + 4, sizeof(len));
                // `off + len` could wrap, so compare against the room left.
                if (len > size || off > size - len) {
                    fatal("contracts: diff run outside the code");
                }
                std::memcpy(dst + off, payload + total, len);
                total += len;
            }
            cursor = payload + total;
            align_to_u64(cursor, runs * 8 + total);
            code = dst;
        } else {
            fatal("contracts: unknown record kind");
        }

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
    return it->second;
}


} // namespace zeg

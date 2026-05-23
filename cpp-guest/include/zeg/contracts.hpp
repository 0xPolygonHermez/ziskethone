// Contracts — bytecode table for the ZisK Ethereum guest.
//
// Holds every contract bytecode the block touches. Each entry is a
// zero-copy slice pointing into the input stream (so the stream must
// outlive this object), tagged with its keccak256 hash. A hashmap from
// keccak hash to array index lets evmc::Host callbacks resolve code by
// hash in expected O(1).

#pragma once

#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg {

class Contracts {
public:
    // One bytecode entry. `code` points into the guest's private-input
    // buffer (zero-copy). `hash` is keccak256(code[0..code_size]).
    struct Contract {
        evmc::bytes32  hash;
        const uint8_t* code;
        uint64_t       code_size;
    };

    // Parse `count` variable-length contract records from `cursor` and
    // build the hash→index lookup. Each record is:
    //   u64       code_size
    //   uint8[]   code
    //   pad       zeros up to the next 8-byte boundary
    // `cursor` is advanced past all bytes consumed (multiple of 8).
    Contracts(uint64_t count, const uint8_t*& cursor);

    // Look up the index of a contract by its keccak code hash. Aborts
    // via zeg::fatal if the hash isn't present (every code the block
    // executes must be in the guest's private input — a missing hash is
    // a hard input-completeness bug).
    size_t index_of(const evmc::bytes32& hash) const;

    // Look up the full Contract record by keccak code hash. Same abort
    // semantics as `index_of`.
    const Contract& by_hash(const evmc::bytes32& hash) const {
        return contracts_[index_of(hash)];
    }

    // Direct positional access (when the index is already known).
    const Contract& at(size_t idx) const { return contracts_[idx]; }

    uint64_t size() const noexcept { return contracts_.size(); }

private:
    // Use the keccak hash bytes directly — already cryptographic-grade
    // random, no further hashing needed.
    struct KeccakAsHash {
        size_t operator()(const evmc::bytes32& h) const noexcept {
            size_t v;
            std::memcpy(&v, h.bytes, sizeof(v));
            return v;
        }
    };
    struct KeccakEq {
        bool operator()(const evmc::bytes32& x, const evmc::bytes32& y) const noexcept {
            return std::memcmp(x.bytes, y.bytes, sizeof(x.bytes)) == 0;
        }
    };

    std::vector<Contract> contracts_;
    std::unordered_map<evmc::bytes32, size_t, KeccakAsHash, KeccakEq> index_;
};

} // namespace zeg

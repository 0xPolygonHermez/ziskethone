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

// Opaque evmc2 pre-analysis handle (the VM defines its layout; a Contract only
// caches a pointer to it). Forward-declared to avoid pulling evmc2.h here.
struct evmc2_pre_execution;

namespace zeg {

class Contracts {
public:
    // One bytecode entry. `code` points into the guest's private-input
    // buffer (zero-copy). `hash` is keccak256(code[0..code_size]).
    struct Contract {
        evmc::bytes32  hash;
        const uint8_t* code;
        uint64_t       code_size;
        // Pre-analysis handle for this bytecode (jumpdest map etc.), prepared
        // once per block on first execution and reused across calls. Owned by
        // the VM that produced it (via evmc2 prepare/release); `mutable` so it
        // can be filled lazily through a `const Contract&`. See
        // `Contracts::release_analyses` for teardown.
        mutable ::evmc2_pre_execution* analysis = nullptr;
    };

    // Build the table by reading a `u64` count from `cursor` followed
    // by `count` variable-length contract records. Each record is:
    //   u64       code_size
    //   uint8[]   code
    //   pad       zeros up to the next 8-byte boundary
    // `cursor` is advanced past all bytes consumed (multiple of 8).
    explicit Contracts(const uint8_t*& cursor);

    // Look up the index of a contract by its keccak code hash. Aborts
    // via zeg::fatal if the hash isn't present (every code the block
    // executes must be in the guest's private input — a missing hash is
    // a hard input-completeness bug).
    size_t index_of(const evmc::bytes32& hash) const;

    // Non-fataling probe. Returns true iff `hash` is in the table.
    bool has(const evmc::bytes32& hash) const noexcept {
        return index_.find(hash) != index_.end();
    }

    // Look up the full Contract record by keccak code hash. Same abort
    // semantics as `index_of`.
    const Contract& by_hash(const evmc::bytes32& hash) const {
        return contracts_[index_of(hash)];
    }

    // Direct positional access (when the index is already known).
    const Contract& at(size_t idx) const { return contracts_[idx]; }

    uint64_t size() const noexcept { return contracts_.size(); }

    // Release every prepared analysis handle and clear it. The handles are owned
    // by the VM, so the caller passes a releaser that forwards to the VM's
    // release_pre_execution; this just walks the table. Called on teardown,
    // before the VM is destroyed.
    template <class Release>
    void release_analyses(Release&& release) {
        for (auto& c : contracts_) {
            if (c.analysis != nullptr) {
                release(c.analysis);
                c.analysis = nullptr;
            }
        }
    }

    // Insert a contract deployed at runtime (CREATE/CREATE2). The
    // prover's prestate diff omits contracts that are created and then
    // either SELFDESTRUCT'd or otherwise empty by tx end (even when
    // they're CALL'd in between), so we register their code on the fly
    // here. Bytes are copied into `dynamic_codes_` and survive for the
    // lifetime of this Contracts object — they outlive evmc::Result's
    // release callback for the originating CREATE result. Idempotent:
    // if `hash` is already present, no-ops.
    void insert(const evmc::bytes32& hash,
                const uint8_t* code,
                std::size_t code_size) {
        if (index_.find(hash) != index_.end()) {
            return;
        }
        dynamic_codes_.emplace_back(code, code + code_size);
        const uint8_t* stable = dynamic_codes_.back().data();
        contracts_.push_back(Contract{hash, stable, code_size});
        index_.emplace(hash, contracts_.size() - 1);
    }

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
    // Stable owning storage for runtime-added contract code (via
    // `insert`). The Contract::code pointer for those entries lives
    // here; for input-stream entries it points into the cursor buffer.
    std::vector<std::vector<uint8_t>> dynamic_codes_;
};

} // namespace zeg

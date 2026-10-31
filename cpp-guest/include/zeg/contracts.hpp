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
#include <deque>
#include <unordered_map>
#include <vector>

#include <evmc/evmc.hpp>

#include "zeg/seeded_hash.hpp"
#include "zeg/tx_arena.hpp"

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
        // Deployed by the current transaction: `code` is a copy in the tx
        // arena until settle_staged() keeps or forgets it.
        bool           staged = false;
    };

    // Build the table by reading a `u64` count from `cursor` followed
    // by `count` variable-length contract records. Each record is:
    //   u64       code_size
    //   uint8[]   code
    //   pad       zeros up to the next 8-byte boundary
    // `cursor` is advanced past all bytes consumed (multiple of 8).
    // `seed` keys `index_` with the per-run universal hash
    // (zeg/seeded_hash.hpp); it must outlive the table.
    Contracts(const uint8_t*& cursor, const HashSeed& seed);

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

    // Insert code installed at runtime on account row `owner`: a
    // CREATE/CREATE2 deployment or an EIP-7702 delegation. The prover's
    // prestate diff omits contracts that are created and then either
    // SELFDESTRUCT'd or otherwise empty by tx end (even when they're CALL'd
    // in between), so we register their code on the fly here. Idempotent
    // per hash: an existing entry only records the new owner.
    //
    // The bytes are copied into the tx arena (zeg/tx_arena.hpp), not the
    // never-freed heap: a frame that reverts takes the code with it, and
    // EIP-8037 refunds its state gas, so a transaction could otherwise
    // deploy-and-revert 64 KiB of distinct code per ~39k regular gas and
    // fill the heap (audit B: ~1.7 bytes per gas, a 165M-gas block halted
    // zevm). settle_staged() keeps, at the transaction's end, only the code
    // an owner still has.
    void insert(const evmc::bytes32& hash,
                const uint8_t* code,
                std::size_t code_size,
                std::size_t owner) {
        if (const auto it = index_.find(hash); it != index_.end()) {
            if (contracts_[it->second].staged) {
                staged_.push_back(Staged{it->second, owner});
            }
            return;
        }
        const auto& bytes = staged_codes_.emplace_back(code, code + code_size);
        contracts_.push_back(Contract{hash, bytes.data(), code_size, nullptr, true});
        index_.emplace(hash, contracts_.size() - 1);
        staged_.push_back(Staged{contracts_.size() - 1, owner});
    }

    // End of a transaction or system call, before the tx arena is reset
    // (ZiskStateDB::reset_tx_arena): every revert and SELFDESTRUCT of it has
    // happened. Code whose owner still has its hash (`code_hash_at(owner)`)
    // moves to the heap for the rest of the block; the rest leaves the
    // table, so no later lookup can reach its arena bytes. A forgotten entry
    // stays in the deque (the analysis cache may hold &analysis) with no
    // code; a later deployment of the same code adds a new one.
    template <class CodeHashAt>
    void settle_staged(CodeHashAt&& code_hash_at) {
        for (const Staged& s : staged_) {
            Contract& c = contracts_[s.contract];
            if (c.staged && code_hash_at(s.owner) == c.hash) {
                const auto& kept = dynamic_codes_.emplace_back(c.code, c.code + c.code_size);
                c.code   = kept.data();
                c.staged = false;
            }
        }
        for (const Staged& s : staged_) {
            Contract& c = contracts_[s.contract];
            if (c.staged) {
                index_.erase(c.hash);
                c.code      = nullptr;
                c.code_size = 0;
                c.staged    = false;
            }
        }
        decltype(staged_){}.swap(staged_);
        decltype(staged_codes_){}.swap(staged_codes_);
    }

private:
    // Seeded universal hash over all 32 bytes of the code hash. A keccak is
    // not a safe bucket key on its own: the author picks the code (a
    // delegation stub's 20-byte delegate, a contract's bytes) and so can grind
    // its first bytes into one bucket of the guest's small fixed primes, which
    // made every lookup of a code in that bucket a full chain walk (2^36+
    // steps in one 200M-gas block). See zeg/seeded_hash.hpp.
    struct CodeHashHash {
        const HashSeed* s_ = nullptr;
        size_t operator()(const evmc::bytes32& h) const noexcept {
            return static_cast<size_t>(hash_bytes(*s_, h.bytes, sizeof(h.bytes)));
        }
    };
    struct KeccakEq {
        bool operator()(const evmc::bytes32& x, const evmc::bytes32& y) const noexcept {
            return std::memcmp(x.bytes, y.bytes, sizeof(x.bytes)) == 0;
        }
    };

    // std::deque (not std::vector): the AnalysisCache stores a pointer to a
    // Contract's `analysis` field (&c.analysis). A runtime `insert()` (CREATE/
    // CREATE2/7702 stub) appends, and a vector's reallocation would invalidate
    // every such pointer — leaving the cache able to hand one contract another's
    // analysis (use-after-realloc). A deque never relocates existing elements on
    // push_back, so those pointers stay valid for this object's lifetime.
    std::deque<Contract> contracts_;
    std::unordered_map<evmc::bytes32, size_t, CodeHashHash, KeccakEq> index_;
    // Stable owning storage for runtime-added code that outlived its
    // transaction (settle_staged). The Contract::code pointer for those
    // entries lives here; for input-stream entries it points into the cursor
    // buffer.
    std::vector<std::vector<uint8_t>> dynamic_codes_;

    // This transaction's runtime-added code, in the tx arena (`insert`), and
    // one record per (entry, owner) it was installed on, for settle_staged().
    struct Staged {
        std::size_t contract;  // index into contracts_
        std::size_t owner;     // Accounts row
    };
    using ArenaBytes = std::vector<uint8_t, TxArenaAllocator<uint8_t>>;
    std::vector<ArenaBytes, TxArenaAllocator<ArenaBytes>> staged_codes_;
    std::vector<Staged, TxArenaAllocator<Staged>>         staged_;
};

} // namespace zeg

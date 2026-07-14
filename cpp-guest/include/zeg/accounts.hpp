// Accounts — world-state account table for the ZisK Ethereum guest.
//
// Holds, for every account the block touches:
//   * the *original* (block-start) values, and
//   * an in-memory *modifications* slot tracking any writes performed
//     during EVM re-execution (balance, nonce, codeHash, code).
//
// The table is no longer parsed from a dedicated stream section: it is
// built dynamically by `StateRoot`'s old-root walk, which `append`s one
// row per state-trie leaf (the leaf opcode carries the account's address
// + original fields). The originals live in an owned byte buffer
// (`record_store_`) that `reserve` pre-sizes exactly from the StateRoot
// header's `numberOfAccounts`, so the `View` pointers stay stable as
// rows are appended.
//
// Lookup is by 20-byte address through an internal hashmap. Addresses
// are already pseudo-random (keccak outputs in most cases), so the
// custom hasher just reuses the first 8 bytes of the address as the
// hash value — no extra hashing needed.

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>           // std::assume_aligned
#include <unordered_map>
#include <vector>

#include <evmc/evmc.hpp>

#include "zeg/trie_node.hpp"

namespace zeg {

class Accounts {
public:
    // Internal record stride in bytes. Documented in `View` below. No
    // longer a wire size — the table is built via `append`, not parsed.
    static constexpr uint64_t kRecordSize = 128;

    // Starts empty. Call `reserve(numberOfAccounts)` once, then `append`
    // one row per state-trie leaf during the StateRoot old-root walk.
    Accounts() = default;

    // Pre-size the owned record buffer to exactly `count` rows. Must be
    // called before any `append`, and `count` must equal the number of
    // rows that will be appended (the StateRoot header's
    // `numberOfAccounts`): the buffer is fixed at this size so `View`
    // pointers into it stay stable, and `append` fatals on overflow.
    void reserve(uint64_t count);

    // Append one account row (original/block-start values) and return its
    // index. Registers the address in the lookup map. Fatals if more rows
    // are appended than `reserve` allowed.
    size_t append(const evmc::address&    address,
                  uint64_t                nonce,
                  const evmc::uint256be&  balance,
                  const evmc::bytes32&    code_hash);

    // ----- read accessors (return modified value if dirty, else original) -----
    // Take `tx_idx` and touch the account for EIP-2929 warm tracking
    // (same pattern as Storages). `tx_idx` is the per-block EVM-frame
    // counter that ZiskStateDB bumps for each tx + each system call.
    // These accessors do NOT journal the cold→warm transition; if the
    // calling frame is revertible, the caller must emit a warm entry
    // via `Journal::log_account_warm` BEFORE invoking these.
    evmc::uint256be balance   (const evmc::address& addr, uint64_t tx_idx);
    uint64_t        nonce     (const evmc::address& addr, uint64_t tx_idx);
    evmc::bytes32   code_hash (const evmc::address& addr, uint64_t tx_idx);

    // By-index read accessors. The plain `_at` form returns the *current*
    // value (modification if dirty, else original) — appropriate for
    // post-execution work like computing the new state root. The `_orig_at`
    // form ignores `mods_` and always returns the original from the input
    // stream — appropriate for pre-execution work like verifying the old
    // state root, even after some modifications have already happened.
    const evmc::address&  address_at        (size_t idx) const noexcept;
    evmc::uint256be       balance_at        (size_t idx) const noexcept;
    uint64_t              nonce_at          (size_t idx) const noexcept;
    evmc::bytes32         code_hash_at      (size_t idx) const noexcept;
    const evmc::uint256be& balance_orig_at  (size_t idx) const noexcept;
    uint64_t              nonce_orig_at     (size_t idx) const noexcept;
    const evmc::bytes32&  code_hash_orig_at (size_t idx) const noexcept;

    // ----- state-trie leaf node (owned per row) -----
    //
    // Each row caches the `NodeR` result of its account-trie leaf, the
    // keccak(address) used to rebuild the leaf path, and a `Child` link to
    // its storage-subtree root node. `StateRoot` fills these during the
    // old-root walk and consumes them during the new-root walk.
    //
    // `build_value` (old-root pass) builds the cached leaf from the ORIGINAL
    // fields at path `nib`; `update_value` (new-root pass) recomputes it
    // ONLY if the original fields differ from the current ones or the passed
    // storage root differs from the cached one. Both return a pointer to the
    // row's cached union for the tree walk to consume. `nib` is the leaf's
    // remaining path nibbles; `storage_root` is the hash of the account's
    // storage subtree at the relevant value set.
    const NodeR* build_value(size_t idx,
                             const std::vector<uint8_t>& nib,
                             const evmc::bytes32& addr_hash,
                             Child storage_root_child,
                             const evmc::bytes32& storage_root);
    const NodeR* update_value(size_t idx,
                              const std::vector<uint8_t>& nib,
                              const evmc::bytes32& storage_root);

    const NodeR* cached_at(size_t idx) const noexcept { return &leaf_[idx].cached; }
    Child storage_root_child_at(size_t idx) const noexcept { return leaf_[idx].storage_root; }
    const evmc::bytes32& addr_hash_at(size_t idx) const noexcept { return leaf_[idx].addr_hash; }

    // Setters used by the new-root insert phase to wire a created account's
    // leaf metadata (it was appended at run-time, not via build_value).
    void set_addr_hash(size_t idx, const evmc::bytes32& addr_hash);
    void set_storage_root_child(size_t idx, Child storage_root);

    // True iff none of nonce / balance / code_hash changed since block start.
    bool fields_unchanged_at(size_t idx) const noexcept {
        return nonce_orig_at(idx)     == nonce_at(idx)
            && balance_orig_at(idx)   == balance_at(idx)
            && code_hash_orig_at(idx) == code_hash_at(idx);
    }

    // ----- write accessors (mark the field dirty) -----
    void set_balance   (const evmc::address& addr, const evmc::uint256be& v,
                        uint64_t tx_idx);
    void set_nonce     (const evmc::address& addr, uint64_t v,
                        uint64_t tx_idx);
    void set_code_hash (const evmc::address& addr, const evmc::bytes32& v,
                        uint64_t tx_idx);

    // By-index write accessors. Skip the hashmap lookup; useful for the
    // journal's rollback path where the index is already known. Atomic:
    // they set the field value AND `last_tx_idx` in one call, so the
    // same setter handles both forward writes (caller passes the
    // current `tx_counter_`) and journal rollback (caller passes the
    // pre-write `old_last_tx_idx` so the slot's warmth is restored
    // alongside the value).
    void set_balance_at  (size_t idx, const evmc::uint256be& v, uint64_t tx_idx);
    void set_nonce_at    (size_t idx, uint64_t                v, uint64_t tx_idx);
    void set_code_hash_at(size_t idx, const evmc::bytes32&    v, uint64_t tx_idx);

    // Look up the array index of `addr`. Aborts the guest via zeg::fatal
    // if the address isn't in the table — the guest is supposed to have
    // every state it touches in its private input, so a missing address
    // is a hard input-completeness bug, not a recoverable case.
    size_t index_of(const evmc::address& addr) const;

    // Non-fataling probe — true iff `addr` is in the table.
    bool contains(const evmc::address& addr) const noexcept {
        return index_.find(addr) != index_.end();
    }

    // ----- pre-funded phantom accounts (preimage-less CREATE2 targets) -----
    //
    // A pre-state account with balance but no witness key-preimage arrives as an
    // Op::PhantomLeaf (trie-only, never in this table). If the block CREATEs a
    // contract there, it must inherit that balance. StateRoot records
    // keccak(addr) -> balance at build; ensure_account seeds the created row's
    // balance from it, and calculate_new_state_root supersedes the stale phantom
    // leaf (a non-null lookup here means "this created row superseded a phantom").
    void record_phantom_balance(const evmc::bytes32& addr_hash,
                                const evmc::uint256be& balance);
    const evmc::uint256be* phantom_balance(const evmc::bytes32& addr_hash) const;

    // ----- per-tx warm/cold tracking (EIP-2929) -----
    //
    // Same shape as Storages: `mark_touched_at` bumps `last_tx_idx`
    // iff `tx_idx > last_tx_idx` (idempotent in-tx); `is_warm_at`
    // tells the caller whether the account was already touched in
    // tx `tx_idx`. Warm state IS journaled — but the journaling
    // happens at the caller (ZiskStateDB), which captures the
    // pre-write `last_tx_idx_at(idx)` via `Journal::log_account_warm`
    // BEFORE bumping. The table layer is journal-free; the rollback
    // path uses `set_warm_at` (below) to restore a prior (cooler)
    // `last_tx_idx`, and the value setters above to restore the
    // field + warmth atomically. Unlike Storages we don't keep a
    // per-tx-original snapshot for balance/nonce/code_hash: the EVM
    // has no SSTORE-like status for these, so EIP-2200 is irrelevant.
    void     mark_touched_at(size_t idx, uint64_t tx_idx) noexcept;
    bool     is_warm_at     (size_t idx, uint64_t tx_idx) const noexcept;
    uint64_t last_tx_idx_at (size_t idx) const noexcept;

    // Unconditional setter for `last_tx_idx`. Used by the journal's
    // rollback path to restore the pre-write value (which may be
    // smaller than the current one — `mark_touched_at` only bumps up).
    void     set_warm_at    (size_t idx, uint64_t tx_idx) noexcept;

    uint64_t size() const noexcept { return originals_.size(); }

private:
    // View into one 128-byte record in `record_store_`. Layout:
    //   offset  size  field
    //        0   20   address       (raw bytes)
    //       20    4   pad           (keeps the record 8-aligned past address)
    //       24   32   balance       (big-endian uint256, evmc wire form)
    //       56    8   nonce         (host-endian u64)
    //       64   32   (unused — storage_root is recomputed by StateRoot)
    //       96   32   code_hash     (keccak hash)
    //      128         end of record
    struct View {
        const uint8_t* data;

        static constexpr size_t kAddressOffset     = 0;
        static constexpr size_t kBalanceOffset     = 24;
        static constexpr size_t kNonceOffset       = 56;
        static constexpr size_t kCodeHashOffset    = 96;

        const evmc::address& address() const noexcept {
            return *reinterpret_cast<const evmc::address*>(data + kAddressOffset);
        }
        const evmc::uint256be& balance() const noexcept {
            return *reinterpret_cast<const evmc::uint256be*>(data + kBalanceOffset);
        }
        uint64_t nonce() const noexcept {
            uint64_t v;
            std::memcpy(&v, std::assume_aligned<8>(data + kNonceOffset), sizeof(v));
            return v;
        }
        const evmc::bytes32& code_hash() const noexcept {
            return *reinterpret_cast<const evmc::bytes32*>(data + kCodeHashOffset);
        }
    };

    // One dirty-flag + new-value slot per field. The field is fetched
    // from `View` unless the matching dirty flag is set, in which case
    // the value here wins. `last_tx_idx` tracks EIP-2929 warm state:
    // `mark_touched_at` bumps it on first access in a tx; the field
    // IS journaled via Journal::log_account_warm so a reverted frame
    // restores the prior (possibly cold) value. `last_tx_idx == 0` is
    // the never-touched sentinel; tx_idx starts at 1.
    struct Mods {
        bool balance_dirty   : 1 = false;
        bool nonce_dirty     : 1 = false;
        bool code_hash_dirty : 1 = false;

        evmc::uint256be balance{};
        uint64_t        nonce     = 0;
        evmc::bytes32   code_hash{};

        uint64_t        last_tx_idx = 0;
    };

    // Custom hasher: the address is already a high-entropy 20-byte value
    // (keccak output for EOAs created via CREATE2, or the lower 20 bytes
    // of keccak(sender || nonce) for CREATE — random enough either way),
    // so we just splice its first 8 bytes as the hash.
    struct AddressHash {
        size_t operator()(const evmc::address& a) const noexcept {
            uint64_t v;
            std::memcpy(&v, a.bytes, sizeof(v));
            return static_cast<size_t>(v);
        }
    };
    struct AddressEq {
        bool operator()(const evmc::address& x, const evmc::address& y) const noexcept {
            return std::memcmp(x.bytes, y.bytes, sizeof(x.bytes)) == 0;
        }
    };

    // Per-row state-trie leaf cache (parallel to `originals_`). Owned by
    // the table so the leaf recompute lives next to the values it reads.
    struct LeafCache {
        NodeR         cached{};        // account-leaf NodeR result
        evmc::bytes32 addr_hash{};     // keccak(address) — for the leaf path
        Child         storage_root{};  // link to the storage-subtree root node
    };

    // Owned backing buffer for the original records. Pre-sized exactly by
    // `reserve`; never reallocated afterwards, so the `View` pointers in
    // `originals_` stay valid for the lifetime of the table.
    std::vector<uint8_t> record_store_;
    uint64_t             capacity_ = 0;

    std::vector<View>      originals_;
    std::vector<Mods>      mods_;
    std::vector<LeafCache> leaf_;
    std::unordered_map<evmc::address, size_t, AddressHash, AddressEq> index_;

    // keccak(addr) -> pre-funded balance for phantom (preimage-less) accounts.
    // See record_phantom_balance(). Keyed by hash (the plaintext is unknown);
    // the addr_hash bytes are uniform keccak output, so splice the first 8.
    struct AddrHashHash {
        size_t operator()(const evmc::bytes32& h) const noexcept {
            uint64_t v; std::memcpy(&v, h.bytes, sizeof(v));
            return static_cast<size_t>(v);
        }
    };
    struct AddrHashEq {
        bool operator()(const evmc::bytes32& x, const evmc::bytes32& y) const noexcept {
            return std::memcmp(x.bytes, y.bytes, sizeof(x.bytes)) == 0;
        }
    };
    std::unordered_map<evmc::bytes32, evmc::uint256be, AddrHashHash, AddrHashEq>
        phantom_balance_;
};

} // namespace zeg

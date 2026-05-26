// Accounts — world-state account table for the ZisK Ethereum guest.
//
// Holds, for every account the block touches:
//   * the *original* values (zero-copy view into the input stream), and
//   * an in-memory *modifications* slot tracking any writes performed
//     during EVM re-execution (balance, nonce, codeHash, code).
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

namespace zeg {

class Accounts {
public:
    // Wire-format record size in bytes. Documented in `View` below.
    static constexpr uint64_t kRecordSize = 136;

    // Build the table by reading a `u64` count from `cursor` followed
    // by `count` consecutive 136-byte records. Advances `cursor` past
    // every byte consumed. The buffer must outlive this instance.
    explicit Accounts(const uint8_t*& cursor);

    // ----- read accessors (return modified value if dirty, else original) -----
    // Take `tx_idx` and touch the account for EIP-2929 warm tracking
    // (same pattern as Storages). `tx_idx` is the per-block EVM-frame
    // counter that ZiskStateDB bumps for each tx + each system call.
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
    // storage_root is read straight from the stream view — it can only be
    // updated as a side effect of recomputing the storage trie, never via
    // a setter on Accounts, so this getter returns the original.
    const evmc::bytes32&  storage_root_at   (size_t idx) const noexcept;
    // True iff the input stream marked this account read-only (e.g. a
    // prestate-only access that must not be modified). The flag lives
    // in the stream; there is no setter.
    bool                  is_read_only_at   (size_t idx) const noexcept;

    // ----- write accessors (mark the field dirty) -----
    void set_balance   (const evmc::address& addr, const evmc::uint256be& v,
                        uint64_t tx_idx);
    void set_nonce     (const evmc::address& addr, uint64_t v,
                        uint64_t tx_idx);
    void set_code_hash (const evmc::address& addr, const evmc::bytes32& v,
                        uint64_t tx_idx);

    // By-index write accessors. Skip the hashmap lookup; useful for the
    // journal's rollback path where the index is already known.
    void set_balance_at  (size_t idx, const evmc::uint256be& v);
    void set_nonce_at    (size_t idx, uint64_t v);
    void set_code_hash_at(size_t idx, const evmc::bytes32& v);

    // Look up the array index of `addr`. Aborts the guest via zeg::fatal
    // if the address isn't in the table — the guest is supposed to have
    // every state it touches in its private input, so a missing address
    // is a hard input-completeness bug, not a recoverable case.
    size_t index_of(const evmc::address& addr) const;

    // ----- per-tx warm/cold tracking (EIP-2929) -----
    //
    // Same shape as Storages: `mark_touched_at` bumps `last_tx_idx`
    // iff `tx_idx > last_tx_idx` (idempotent in-tx); `is_warm_at`
    // tells the caller whether the account was already touched in
    // tx `tx_idx`. `last_tx_idx` is NOT journaled — warm state
    // survives intra-tx reverts per EIP-2929. Unlike Storages we
    // don't keep a per-tx-original snapshot for the field values:
    // the EVM has no SSTORE-like status for balance/nonce/code_hash,
    // so the EIP-2200 machinery is irrelevant here.
    void mark_touched_at(size_t idx, uint64_t tx_idx) noexcept;
    bool is_warm_at     (size_t idx, uint64_t tx_idx) const noexcept;

    uint64_t size() const noexcept { return originals_.size(); }

private:
    // Zero-copy view into one 136-byte record. Wire layout:
    //   offset  size  field
    //        0   20   address       (raw bytes)
    //       20    4   pad           (keeps cursor 8-aligned past address)
    //       24   32   balance       (big-endian uint256, evmc wire form)
    //       56    8   nonce         (little-endian u64)
    //       64   32   storage_root  (keccak hash)
    //       96   32   code_hash     (keccak hash)
    //      128    8   is_read_only  (u64, 1 = true, 0 = false)
    //      136         end of record
    struct View {
        const uint8_t* data;

        static constexpr size_t kAddressOffset     = 0;
        static constexpr size_t kBalanceOffset     = 24;
        static constexpr size_t kNonceOffset       = 56;
        static constexpr size_t kStorageRootOffset = 64;
        static constexpr size_t kCodeHashOffset    = 96;
        static constexpr size_t kIsReadOnlyOffset  = 128;

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
        const evmc::bytes32& storage_root() const noexcept {
            return *reinterpret_cast<const evmc::bytes32*>(data + kStorageRootOffset);
        }
        const evmc::bytes32& code_hash() const noexcept {
            return *reinterpret_cast<const evmc::bytes32*>(data + kCodeHashOffset);
        }
        bool is_read_only() const noexcept {
            uint64_t v;
            std::memcpy(&v, std::assume_aligned<8>(data + kIsReadOnlyOffset), sizeof(v));
            return v != 0;
        }
    };

    // One dirty-flag + new-value slot per field. The field is fetched
    // from `View` unless the matching dirty flag is set, in which case
    // the value here wins. `last_tx_idx` tracks EIP-2929 warm state:
    // `mark_touched_at` bumps it on first access in a tx; the field
    // is NOT journaled (warm state survives intra-tx reverts).
    // `last_tx_idx == 0` is the never-touched sentinel; tx_idx
    // starts at 1.
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

    std::vector<View> originals_;
    std::vector<Mods> mods_;
    std::unordered_map<evmc::address, size_t, AddressHash, AddressEq> index_;
};

} // namespace zeg

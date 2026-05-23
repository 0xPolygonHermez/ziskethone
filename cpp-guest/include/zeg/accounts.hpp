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
    static constexpr uint64_t kRecordSize = 128;

    // Build the table from `count` consecutive 128-byte records starting
    // at `data`. The buffer must outlive this Accounts instance.
    Accounts(uint64_t count, const uint8_t* data);

    // ----- read accessors (return modified value if dirty, else original) -----
    evmc::uint256be balance   (const evmc::address& addr) const;
    uint64_t        nonce     (const evmc::address& addr) const;
    evmc::bytes32   code_hash (const evmc::address& addr) const;

    // By-index read accessors. Used when the caller already has the index
    // (e.g. the state-root walker iterating accounts_ by row).
    const evmc::address& address_at     (size_t idx) const noexcept;
    evmc::uint256be      balance_at     (size_t idx) const noexcept;
    uint64_t             nonce_at       (size_t idx) const noexcept;
    evmc::bytes32        code_hash_at   (size_t idx) const noexcept;
    // storage_root is read straight from the stream view — it can only be
    // updated as a side effect of recomputing the storage trie, never via
    // a setter on Accounts, so this getter returns the original.
    const evmc::bytes32& storage_root_at(size_t idx) const noexcept;

    // ----- write accessors (mark the field dirty) -----
    void set_balance   (const evmc::address& addr, const evmc::uint256be& v);
    void set_nonce     (const evmc::address& addr, uint64_t v);
    void set_code_hash (const evmc::address& addr, const evmc::bytes32& v);

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

    uint64_t size() const noexcept { return originals_.size(); }

private:
    // Zero-copy view into one 128-byte record. Wire layout:
    //   offset  size  field
    //        0   20   address       (raw bytes)
    //       20    4   pad           (keeps cursor 8-aligned past address)
    //       24   32   balance       (big-endian uint256, evmc wire form)
    //       56    8   nonce         (little-endian u64)
    //       64   32   storage_root  (keccak hash)
    //       96   32   code_hash     (keccak hash)
    //      128         end of record
    struct View {
        const uint8_t* data;

        static constexpr size_t kAddressOffset     = 0;
        static constexpr size_t kBalanceOffset     = 24;
        static constexpr size_t kNonceOffset       = 56;
        static constexpr size_t kStorageRootOffset = 64;
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
        const evmc::bytes32& storage_root() const noexcept {
            return *reinterpret_cast<const evmc::bytes32*>(data + kStorageRootOffset);
        }
        const evmc::bytes32& code_hash() const noexcept {
            return *reinterpret_cast<const evmc::bytes32*>(data + kCodeHashOffset);
        }
    };

    // One dirty-flag + new-value slot per field. The field is fetched
    // from `View` unless the matching dirty flag is set, in which case
    // the value here wins.
    struct Mods {
        bool balance_dirty   : 1 = false;
        bool nonce_dirty     : 1 = false;
        bool code_hash_dirty : 1 = false;

        evmc::uint256be balance{};
        uint64_t        nonce     = 0;
        evmc::bytes32   code_hash{};
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

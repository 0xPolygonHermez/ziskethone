// Storages — per-account storage-slot table for the ZisK Ethereum guest.
//
// Holds, for every (account, slot) pair the block touches:
//   * the *original* slot value (zero-copy view into the input stream), and
//   * an in-memory dirty/new-value pair tracking any SSTORE performed
//     during EVM re-execution.
//
// Lookup is by the composite (address, position) pair through an internal
// hashmap. Both halves are already pseudo-random (keccak outputs / slot
// indices), so the custom hasher just XORs the lowest 8 bytes of each.

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>           // std::assume_aligned
#include <unordered_map>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg {

class Storages {
public:
    // Wire-format record size in bytes. Documented in `View` below.
    static constexpr uint64_t kRecordSize = 96;

    // Build the table by reading a `u64` count from `cursor` followed
    // by `count` consecutive 96-byte records. Advances `cursor` past
    // every byte consumed. The buffer must outlive this instance.
    explicit Storages(const uint8_t*& cursor);

    // Returns the current slot value: the dirty new value if `set_value`
    // has been called for this (addr, position), else the original from
    // the stream. Aborts via zeg::fatal if (addr, position) is not
    // present. Also touches the slot for tx `tx_idx` (snapshots the
    // pre-tx value into `tx_original_at(idx)` if this is the first
    // access in this tx) so the EVM sees the correct EIP-2929 warm
    // state and EIP-2200 original on subsequent calls.
    evmc::bytes32 value(const evmc::address& addr,
                        const evmc::bytes32& position,
                        uint64_t              tx_idx);

    // Records a new value for the slot. Aborts via zeg::fatal if (addr,
    // position) is not present. Touches the slot for `tx_idx` (same
    // snapshot semantics as `value()`).
    void set_value(const evmc::address& addr,
                   const evmc::bytes32& position,
                   const evmc::bytes32& v,
                   uint64_t              tx_idx);

    // By-index write accessor. Skips the hashmap lookup; useful for the
    // journal's rollback path where the index is already known.
    void set_value_at(size_t idx, const evmc::bytes32& v);

    // By-index read accessors. `value_at` returns the *current* value
    // (modification if dirty, else original); `value_orig_at` always
    // returns the original from the input stream. address / position
    // are immutable post-construction so a single accessor suffices.
    const evmc::address&  address_at     (size_t idx) const noexcept;
    const evmc::bytes32&  position_at    (size_t idx) const noexcept;
    evmc::bytes32         value_at       (size_t idx) const noexcept;
    const evmc::bytes32&  value_orig_at  (size_t idx) const noexcept;
    // True iff the input stream marked this slot read-only. The flag
    // lives in the stream; there is no setter.
    bool                  is_read_only_at(size_t idx) const noexcept;

    // Look up the array index of (addr, position). Aborts the guest via
    // zeg::fatal if the slot isn't in the table — the guest is supposed
    // to have every state it touches in its private input, so a missing
    // slot is a hard input-completeness bug, not a recoverable case.
    size_t index_of(const evmc::address& addr,
                    const evmc::bytes32& position) const;

    // ----- per-tx tracking (EIP-2929 warm/cold + EIP-2200 originals) -----
    //
    // When a tx first touches a slot, snapshot the current value into
    // `tx_original` and bump `last_tx_idx`. Idempotent within a tx.
    // These fields are NEVER journaled — per EIP-2929 the warm state
    // and per-tx-original survive intra-tx reverts.
    void                 mark_touched_at(size_t idx, uint64_t tx_idx) noexcept;

    // True iff this slot was touched in tx `tx_idx` (= warm for it).
    bool                 is_warm_at(size_t idx, uint64_t tx_idx) const noexcept;

    // Value at the start of the tx that last touched this slot. Only
    // meaningful when `is_warm_at(idx, current_tx_idx) == true`.
    const evmc::bytes32& tx_original_at(size_t idx) const noexcept;

    uint64_t size() const noexcept { return originals_.size(); }

private:
    // Zero-copy view into one 96-byte record. Wire layout:
    //   offset  size  field
    //        0   20   address       (raw bytes)
    //       20    4   pad           (keeps cursor 8-aligned past address)
    //       24   32   position      (storage slot key)
    //       56   32   value         (slot value)
    //       88    8   is_read_only  (u64, 1 = true, 0 = false)
    //       96         end of record
    struct View {
        const uint8_t* data;

        static constexpr size_t kAddressOffset    = 0;
        static constexpr size_t kPositionOffset   = 24;
        static constexpr size_t kValueOffset      = 56;
        static constexpr size_t kIsReadOnlyOffset = 88;

        const evmc::address& address() const noexcept {
            return *reinterpret_cast<const evmc::address*>(data + kAddressOffset);
        }
        const evmc::bytes32& position() const noexcept {
            return *reinterpret_cast<const evmc::bytes32*>(data + kPositionOffset);
        }
        const evmc::bytes32& value() const noexcept {
            return *reinterpret_cast<const evmc::bytes32*>(data + kValueOffset);
        }
        bool is_read_only() const noexcept {
            uint64_t v;
            std::memcpy(&v, std::assume_aligned<8>(data + kIsReadOnlyOffset), sizeof(v));
            return v != 0;
        }
    };

    // Per-slot mutation slot. The slot value is fetched from `View`
    // unless `dirty` is set, in which case `value` here wins.
    //
    // `last_tx_idx` / `tx_original` track EIP-2929 warm state and
    // EIP-2200 per-tx-original: on the first touch in a tx,
    // `mark_touched_at` snapshots the slot's current value into
    // `tx_original` and bumps `last_tx_idx` to the tx counter. These
    // two fields are NOT journaled — warm state survives intra-tx
    // reverts per EIP-2929. `last_tx_idx == 0` is the never-touched
    // sentinel; the tx counter starts at 1.
    struct Mods {
        bool          dirty : 1   = false;
        evmc::bytes32 value{};
        uint64_t      last_tx_idx = 0;
        evmc::bytes32 tx_original{};
    };

    // Composite map key: 20-byte address + 32-byte slot key. Trivially
    // copyable, no internal padding (both members are uint8_t arrays).
    struct Key {
        evmc::address address;
        evmc::bytes32 position;
    };
    static_assert(sizeof(Key) == 20 + 32, "Key must be tightly packed");

    // Hash: XOR the lowest 8 bytes of address and position. Both halves
    // are high-entropy big-endian quantities, so XOR-ing their LSB ends
    // produces a good distribution with one byte-fetch from each.
    struct KeyHash {
        size_t operator()(const Key& k) const noexcept {
            uint64_t a;
            std::memcpy(&a, k.address.bytes  + sizeof(k.address.bytes)  - 8, 8);
            uint64_t p;
            std::memcpy(&p, k.position.bytes + sizeof(k.position.bytes) - 8, 8);
            return static_cast<size_t>(a ^ p);
        }
    };
    struct KeyEq {
        bool operator()(const Key& x, const Key& y) const noexcept {
            return std::memcmp(&x, &y, sizeof(x)) == 0;
        }
    };

    std::vector<View> originals_;
    std::vector<Mods> mods_;
    std::unordered_map<Key, size_t, KeyHash, KeyEq> index_;
};

} // namespace zeg

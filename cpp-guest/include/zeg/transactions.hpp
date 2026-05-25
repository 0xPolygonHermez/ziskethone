// Transactions — every tx in the current block, eagerly parsed once from
// the canonical RLP envelopes the prover provides.
//
// Each tx is decoded at construction into typed fields stored inside a
// View. The canonical transaction hash and the recovered sender
// address are both precomputed: the prover supplies the sender's
// uncompressed secp256k1 public key alongside each envelope, the
// constructor verifies the signature against it via ZisK's
// secp256k1_ecdsa_verify syscall, then derives the sender as
// keccak256(pubkey)[12:]. The intermediate signing hash and the pubkey
// itself are not retained.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

namespace zeg {

class Transactions {
public:
    // Canonical tx-type tag.
    enum class Type : uint8_t {
        Legacy     = 0,  // pre-EIP-2718
        AccessList = 1,  // EIP-2930
        DynamicFee = 2,  // EIP-1559
        Blob       = 3,  // EIP-4844
        SetCode    = 4,  // EIP-7702
        Osaka      = 5,  // EIP-7873 — TXCREATE InitcodeTransaction
    };

    // One transaction, fully parsed. All fields valid for the tx's type
    // are populated at construction; accessors that don't apply to the
    // type (e.g. gas_price() on a DynamicFee tx) abort via zeg::fatal.
    class View {
    public:
        Type                       type()             const noexcept { return type_; }
        const evmc::bytes32&       transaction_hash() const noexcept { return transaction_hash_; }
        const evmc::address&       sender()           const noexcept { return sender_; }

        // ----- common across all types -----
        uint64_t                   nonce()         const noexcept { return nonce_; }
        uint64_t                   gas_limit()     const noexcept { return gas_limit_; }
        // null for contract creation.
        const evmc::address*       to()            const noexcept { return to_present_ ? &to_ : nullptr; }
        const evmc::uint256be&     value()         const noexcept { return value_; }
        std::span<const uint8_t>   data()          const noexcept { return data_; }

        // Legacy uses the chain-encoded v; typed txs use yParity (0/1) in
        // the same slot.
        uint64_t                   v_or_y_parity() const noexcept { return v_or_y_parity_; }
        const evmc::uint256be&     r()             const noexcept { return r_; }
        const evmc::uint256be&     s()             const noexcept { return s_; }

        // ----- chain id -----
        // Legacy pre-EIP-155 returns 0; legacy EIP-155 derives chain_id
        // from v as (v - 35) / 2; typed txs use the explicit field.
        uint64_t                   chain_id()      const noexcept { return chain_id_; }

        // ----- fee market -----
        // Legacy / AccessList: gas_price().
        // DynamicFee / Blob / SetCode / Osaka: max_priority_fee_per_gas() + max_fee_per_gas().
        const evmc::uint256be&     gas_price()                const;
        const evmc::uint256be&     max_priority_fee_per_gas() const;
        const evmc::uint256be&     max_fee_per_gas()          const;

        // ----- access list (typed txs only; legacy returns empty span) -----
        // Returned as the raw RLP encoding of the list (header + payload),
        // so it can be re-spliced into the signing-hash re-encoder or
        // walked via decode_item + ListIter.
        std::span<const uint8_t>   access_list_rlp() const noexcept { return access_list_rlp_; }

        // ----- blob-specific (Type 3 only; others abort) -----
        const evmc::uint256be&     max_fee_per_blob_gas()      const;
        std::span<const uint8_t>   blob_versioned_hashes_rlp() const;

        // ----- EIP-7702 (Type 4 only; others abort) -----
        std::span<const uint8_t>   authorization_list_rlp() const;
        // Number of authorization-signer pubkeys the prover supplied
        // for this tx. For Type 4 this equals the auth-list length;
        // for other types it's always 0.
        size_t                     num_auth_pubkeys() const noexcept { return num_auth_pubkeys_; }
        // Returns the 64-byte (x || y, big-endian) pubkey for the
        // i-th authorization. Aborts via zeg::fatal if `i` is out of
        // range.
        std::span<const uint8_t>   auth_pubkey(size_t i) const;

        // ----- EIP-7873 / Osaka (Type 5 only; others abort) -----
        // Raw RLP of the TXCREATE initcode pool (a list of byte
        // strings, each entry is one initcode). The executor walks it
        // with rlp::ListIter when feeding evmc_tx_context::initcodes.
        std::span<const uint8_t>   initcodes_rlp() const;

    private:
        friend class Transactions;

        Type           type_{Type::Legacy};
        evmc::bytes32  transaction_hash_{};
        evmc::address  sender_{};

        // ----- common -----
        uint64_t                 nonce_{0};
        uint64_t                 gas_limit_{0};
        evmc::address            to_{};
        bool                     to_present_{false};
        evmc::uint256be          value_{};
        std::span<const uint8_t> data_{};

        uint64_t                 v_or_y_parity_{0};
        evmc::uint256be          r_{};
        evmc::uint256be          s_{};

        // ----- chain id -----
        uint64_t                 chain_id_{0};

        // ----- fee market -----
        evmc::uint256be          gas_price_{};
        evmc::uint256be          max_priority_fee_per_gas_{};
        evmc::uint256be          max_fee_per_gas_{};

        // Raw RLP (header + payload) of nested-list fields; empty for
        // types that don't have them.
        std::span<const uint8_t> access_list_rlp_{};

        // ----- blob (Type 3) -----
        evmc::uint256be          max_fee_per_blob_gas_{};
        std::span<const uint8_t> blob_versioned_hashes_rlp_{};

        // ----- EIP-7702 (Type 4) -----
        std::span<const uint8_t> authorization_list_rlp_{};
        // Prover-supplied uncompressed pubkeys, one per auth entry,
        // laid out contiguously (64 B each). Pointer into the input
        // stream; the stream must outlive this View.
        const uint8_t*           auth_pubkeys_{nullptr};
        size_t                   num_auth_pubkeys_{0};

        // ----- EIP-7873 / Osaka (Type 5) -----
        std::span<const uint8_t> initcodes_rlp_{};
    };

    // Parse `u64 count` followed by `count` × (`u64 envelope_size +
    // pubkey[64] + envelope bytes + pad-to-8`). Each tx is fully
    // decoded into its View; the transaction hash is computed,
    // signature verified against the supplied pubkey, and sender
    // derived. `cursor` is advanced past every byte consumed.
    explicit Transactions(const uint8_t*& cursor);

    size_t      size() const noexcept { return views_.size(); }
    const View& at(size_t idx) const  { return views_[idx]; }

private:
    // Per-type parsers. Each consumes the outer RLP list payload (after
    // the optional type-byte prefix has been stripped) and writes every
    // field into `v`. Implemented as static members of Transactions so
    // they can reach View's private state via the `friend Transactions`
    // grant.
    static void parse_legacy     (View& v, std::span<const uint8_t> outer_payload);
    static void parse_access_list(View& v, std::span<const uint8_t> outer_payload);
    static void parse_dynamic_fee(View& v, std::span<const uint8_t> outer_payload);
    static void parse_blob       (View& v, std::span<const uint8_t> outer_payload);
    static void parse_set_code   (View& v, std::span<const uint8_t> outer_payload);
    static void parse_osaka      (View& v, std::span<const uint8_t> outer_payload);

    std::vector<View> views_;
};

} // namespace zeg

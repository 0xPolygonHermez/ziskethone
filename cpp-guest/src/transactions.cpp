#include "zeg/transactions.hpp"

#include <cstring>
#include <utility>

#include "zeg/fatal.hpp"
#include "zeg/keccak.hpp"
#include "zeg/mpt.hpp"
#include "zeg/rlp.hpp"
#include "zeg/stream.hpp"
#include "zeg/zisk_crypto.hpp"

namespace zeg {

namespace {

using rlp::Bytes;
using rlp::BytesView;
using rlp::Item;
using rlp::ItemKind;
using rlp::ListIter;
using rlp::as_u64;
using rlp::as_u256;

// ============================================================================
// Item → typed value converters.
// ============================================================================

// Decode an RLP string as a raw byte span (zero-copy into the envelope).
std::span<const uint8_t> as_bytes(const Item& it) {
    if (it.kind != ItemKind::String) {
        fatal("Transactions: expected RLP string for bytes field");
    }
    return it.payload;
}

// Return the raw RLP encoding (header + payload) of a nested list,
// asserting that the item really is a list. Used for fields whose
// structured contents the executor walks later but which the signing-
// hash re-encoder needs to splice in verbatim.
std::span<const uint8_t> as_list_raw(const Item& it) {
    if (it.kind != ItemKind::List) {
        fatal("Transactions: expected RLP list");
    }
    return it.raw;
}

// Pull the next item off the iterator, aborting if the list is shorter
// than the per-type schema expects.
Item next_required(ListIter& it) {
    if (!it.has_next()) {
        fatal("Transactions: tx RLP list shorter than required");
    }
    return it.next();
}

// Require the outer tx list to be fully consumed after the last schema field
// (`s`). Extra trailing fields make the envelope non-canonical — a block the
// network rejects — so the guest must not accept it.
void require_end(ListIter& it) {
    if (it.has_next()) {
        fatal("Transactions: tx RLP list has trailing fields");
    }
}

// `to` is either an empty string (contract creation) or a 20-byte
// address. Anything else is malformed.
void parse_to(Transactions::View& v, const Item& it,
              evmc::address& addr_out, bool& present_out) {
    (void)v;
    if (it.kind != ItemKind::String) {
        fatal("Transactions: `to` is not a string");
    }
    if (it.payload.empty()) {
        present_out = false;
    } else if (it.payload.size() == 20) {
        present_out = true;
        std::memcpy(addr_out.bytes, it.payload.data(), 20);
    } else {
        fatal("Transactions: `to` length must be 0 or 20");
    }
}

// Encode `to` for the signing-hash re-encoder.
Bytes encode_to(const Transactions::View& v) {
    if (v.to() == nullptr) {
        return rlp::encode(BytesView{});
    }
    return rlp::encode(BytesView{v.to()->bytes, 20});
}

// ============================================================================
// Signing-hash computation (file-local — not part of the public API).
//
// Each tx type defines a canonical RLP encoding *without* the signature
// fields (v/r/s); the signing hash is keccak256 of that pre-image, with
// a 1-byte type prefix for typed txs (EIP-2718). Legacy uses two
// encodings depending on whether EIP-155 chain replay protection is in
// effect.
// ============================================================================

evmc::bytes32 compute_signing_hash(const Transactions::View& v) {
    using rlp::encode;
    using rlp::encode_list;
    using rlp::encode_u64;
    using rlp::encode_u256;
    using Type = Transactions::Type;

    const Bytes nonce_enc     = encode_u64 (v.nonce());
    const Bytes gas_limit_enc = encode_u64 (v.gas_limit());
    const Bytes value_enc     = encode_u256(v.value());
    const Bytes data_enc      = encode      (v.data());
    const Bytes to_enc        = encode_to(v);

    Bytes preimage;

    switch (v.type()) {
        case Type::Legacy: {
            const Bytes gas_price_enc = encode_u256(v.gas_price());
            if (v.v_or_y_parity() >= 35) {
                // EIP-155: 9-field pre-image with chain_id and two empty
                // strings (r=0, s=0) appended.
                const Bytes chain_id_enc = encode_u64(v.chain_id());
                const Bytes zero_enc     = encode_u64(0);
                preimage = encode_list({
                    nonce_enc, gas_price_enc, gas_limit_enc,
                    to_enc,    value_enc,     data_enc,
                    chain_id_enc, zero_enc,   zero_enc,
                });
            } else {
                // Pre-EIP-155: 6 fields, no chain id.
                preimage = encode_list({
                    nonce_enc, gas_price_enc, gas_limit_enc,
                    to_enc,    value_enc,     data_enc,
                });
            }
            break;
        }
        case Type::AccessList: {
            const Bytes chain_id_enc  = encode_u64 (v.chain_id());
            const Bytes gas_price_enc = encode_u256(v.gas_price());
            const Bytes list_bytes    = encode_list({
                chain_id_enc, nonce_enc,    gas_price_enc, gas_limit_enc,
                to_enc,       value_enc,    data_enc,      v.access_list_rlp(),
            });
            preimage.reserve(1 + list_bytes.size());
            preimage.push_back(0x01);
            preimage.insert(preimage.end(), list_bytes.begin(), list_bytes.end());
            break;
        }
        case Type::DynamicFee: {
            const Bytes chain_id_enc = encode_u64 (v.chain_id());
            const Bytes max_pri_enc  = encode_u256(v.max_priority_fee_per_gas());
            const Bytes max_fee_enc  = encode_u256(v.max_fee_per_gas());
            const Bytes list_bytes   = encode_list({
                chain_id_enc, nonce_enc,    max_pri_enc, max_fee_enc,
                gas_limit_enc, to_enc,      value_enc,   data_enc,
                v.access_list_rlp(),
            });
            preimage.reserve(1 + list_bytes.size());
            preimage.push_back(0x02);
            preimage.insert(preimage.end(), list_bytes.begin(), list_bytes.end());
            break;
        }
        case Type::Blob: {
            const Bytes chain_id_enc = encode_u64 (v.chain_id());
            const Bytes max_pri_enc  = encode_u256(v.max_priority_fee_per_gas());
            const Bytes max_fee_enc  = encode_u256(v.max_fee_per_gas());
            const Bytes max_blob_enc = encode_u256(v.max_fee_per_blob_gas());
            const Bytes list_bytes   = encode_list({
                chain_id_enc, nonce_enc,    max_pri_enc, max_fee_enc,
                gas_limit_enc, to_enc,      value_enc,   data_enc,
                v.access_list_rlp(),
                max_blob_enc, v.blob_versioned_hashes_rlp(),
            });
            preimage.reserve(1 + list_bytes.size());
            preimage.push_back(0x03);
            preimage.insert(preimage.end(), list_bytes.begin(), list_bytes.end());
            break;
        }
        case Type::SetCode: {
            const Bytes chain_id_enc = encode_u64 (v.chain_id());
            const Bytes max_pri_enc  = encode_u256(v.max_priority_fee_per_gas());
            const Bytes max_fee_enc  = encode_u256(v.max_fee_per_gas());
            const Bytes list_bytes   = encode_list({
                chain_id_enc, nonce_enc,    max_pri_enc, max_fee_enc,
                gas_limit_enc, to_enc,      value_enc,   data_enc,
                v.access_list_rlp(), v.authorization_list_rlp(),
            });
            preimage.reserve(1 + list_bytes.size());
            preimage.push_back(0x04);
            preimage.insert(preimage.end(), list_bytes.begin(), list_bytes.end());
            break;
        }
        case Type::Osaka: {
            const Bytes chain_id_enc = encode_u64 (v.chain_id());
            const Bytes max_pri_enc  = encode_u256(v.max_priority_fee_per_gas());
            const Bytes max_fee_enc  = encode_u256(v.max_fee_per_gas());
            const Bytes list_bytes   = encode_list({
                chain_id_enc, nonce_enc,    max_pri_enc, max_fee_enc,
                gas_limit_enc, to_enc,      value_enc,   data_enc,
                v.access_list_rlp(), v.initcodes_rlp(),
            });
            preimage.reserve(1 + list_bytes.size());
            preimage.push_back(0x05);
            preimage.insert(preimage.end(), list_bytes.begin(), list_bytes.end());
            break;
        }
    }

    return keccak256_bytes32(preimage.data(), preimage.size());
}

// ============================================================================
// Sender recovery (file-local).
//
// The sender is recovered from the envelope's signature alone — no
// prover-supplied public key. The recovery id comes from the tx's own
// v / y_parity field, and ecrecover_address (secp256k1_ecdsa_recover,
// fp_sqrt-fcall accelerated on ZisK) reconstructs the pubkey and derives
// sender = keccak256(pubkey)[12:].
// ============================================================================

// Recover the sender of `v` from its (r, s, v/y_parity) signature over the
// signing hash. Aborts via zeg::fatal on any failure (a tx inside a block
// must carry a recoverable signature).
evmc::address recover_sender(const Transactions::View& v) {
    const evmc::bytes32 z = compute_signing_hash(v);

    // Recovery id: legacy pre-EIP-155 v in {27, 28} -> v - 27;
    // EIP-155 v = 35 + 2*chain_id + parity -> (v - 35) & 1;
    // typed txs carry y_parity (0 or 1) directly.
    const uint64_t vv = v.v_or_y_parity();
    unsigned recid;
    if (v.type() == Transactions::Type::Legacy) {
        if (vv == 27 || vv == 28)  recid = static_cast<unsigned>(vv - 27);
        else if (vv >= 35)         recid = static_cast<unsigned>((vv - 35) & 1);
        else fatal("Transactions: invalid legacy signature v");
    } else {
        if (vv > 1) fatal("Transactions: invalid y_parity");
        recid = static_cast<unsigned>(vv);
    }

    // EIP-2: the signature must be low-s (s in [1, secp256k1n/2]). A high-s
    // signature recovers the same sender and executes identically, but it is a
    // distinct, non-canonical envelope that every conforming EL rejects — so
    // the block the guest would commit to is one the network refuses. (The
    // ECRECOVER precompile 0x01 stays malleable; this gate is tx-only.)
    if (!is_canonical_low_s(v.s())) {
        fatal("Transactions: signature s is not low-s (EIP-2)");
    }

    evmc::address sender;
    if (!ecrecover_address(z, v.r(), v.s(), recid, sender)) {
        fatal("Transactions: sender recovery failed");
    }
    return sender;
}

} // namespace

// ============================================================================
// View accessors with type guards.
// ============================================================================

const evmc::uint256be& Transactions::View::gas_price() const {
    if (type_ != Type::Legacy && type_ != Type::AccessList) {
        fatal("Transactions::View::gas_price: tx type has no gas_price");
    }
    return gas_price_;
}

const evmc::uint256be& Transactions::View::max_priority_fee_per_gas() const {
    if (type_ != Type::DynamicFee && type_ != Type::Blob &&
        type_ != Type::SetCode    && type_ != Type::Osaka) {
        fatal("Transactions::View::max_priority_fee_per_gas: wrong tx type");
    }
    return max_priority_fee_per_gas_;
}

const evmc::uint256be& Transactions::View::max_fee_per_gas() const {
    if (type_ != Type::DynamicFee && type_ != Type::Blob &&
        type_ != Type::SetCode    && type_ != Type::Osaka) {
        fatal("Transactions::View::max_fee_per_gas: wrong tx type");
    }
    return max_fee_per_gas_;
}

const evmc::uint256be& Transactions::View::max_fee_per_blob_gas() const {
    if (type_ != Type::Blob) {
        fatal("Transactions::View::max_fee_per_blob_gas: not a blob tx");
    }
    return max_fee_per_blob_gas_;
}

std::span<const uint8_t> Transactions::View::blob_versioned_hashes_rlp() const {
    if (type_ != Type::Blob) {
        fatal("Transactions::View::blob_versioned_hashes_rlp: not a blob tx");
    }
    return blob_versioned_hashes_rlp_;
}

std::span<const uint8_t> Transactions::View::authorization_list_rlp() const {
    if (type_ != Type::SetCode) {
        fatal("Transactions::View::authorization_list_rlp: not a SetCode tx");
    }
    return authorization_list_rlp_;
}


std::span<const uint8_t> Transactions::View::initcodes_rlp() const {
    if (type_ != Type::Osaka) {
        fatal("Transactions::View::initcodes_rlp: not an Osaka tx");
    }
    return initcodes_rlp_;
}

// ============================================================================
// Per-type RLP parsers — walk the outer list in fixed field order.
// ============================================================================

void Transactions::parse_legacy(View& v, std::span<const uint8_t> outer_payload) {
    ListIter it{outer_payload};
    v.nonce_         = as_u64 (next_required(it));
    v.gas_price_     = as_u256(next_required(it));
    v.gas_limit_     = as_u64 (next_required(it));
    parse_to(v, next_required(it), v.to_, v.to_present_);
    v.value_         = as_u256(next_required(it));
    v.data_          = as_bytes(next_required(it));
    v.v_or_y_parity_ = as_u64 (next_required(it));
    v.r_             = as_u256(next_required(it));
    v.s_             = as_u256(next_required(it));
    require_end(it);

    // EIP-155: chain_id is implicit in v. Pre-EIP-155 legacy txs (v
    // is 27 or 28) carry no chain id.
    v.chain_id_ = v.v_or_y_parity_ >= 35 ? (v.v_or_y_parity_ - 35) / 2 : 0;
}

void Transactions::parse_access_list(View& v, std::span<const uint8_t> outer_payload) {
    ListIter it{outer_payload};
    v.chain_id_        = as_u64 (next_required(it));
    v.nonce_           = as_u64 (next_required(it));
    v.gas_price_       = as_u256(next_required(it));
    v.gas_limit_       = as_u64 (next_required(it));
    parse_to(v, next_required(it), v.to_, v.to_present_);
    v.value_           = as_u256(next_required(it));
    v.data_            = as_bytes(next_required(it));
    v.access_list_rlp_ = as_list_raw(next_required(it));
    v.v_or_y_parity_   = as_u64 (next_required(it));
    v.r_               = as_u256(next_required(it));
    v.s_               = as_u256(next_required(it));
    require_end(it);
}

void Transactions::parse_dynamic_fee(View& v, std::span<const uint8_t> outer_payload) {
    ListIter it{outer_payload};
    v.chain_id_                 = as_u64 (next_required(it));
    v.nonce_                    = as_u64 (next_required(it));
    v.max_priority_fee_per_gas_ = as_u256(next_required(it));
    v.max_fee_per_gas_          = as_u256(next_required(it));
    v.gas_limit_                = as_u64 (next_required(it));
    parse_to(v, next_required(it), v.to_, v.to_present_);
    v.value_                    = as_u256(next_required(it));
    v.data_                     = as_bytes(next_required(it));
    v.access_list_rlp_          = as_list_raw(next_required(it));
    v.v_or_y_parity_            = as_u64 (next_required(it));
    v.r_                        = as_u256(next_required(it));
    v.s_                        = as_u256(next_required(it));
    require_end(it);
}

void Transactions::parse_blob(View& v, std::span<const uint8_t> outer_payload) {
    ListIter it{outer_payload};
    v.chain_id_                  = as_u64 (next_required(it));
    v.nonce_                     = as_u64 (next_required(it));
    v.max_priority_fee_per_gas_  = as_u256(next_required(it));
    v.max_fee_per_gas_           = as_u256(next_required(it));
    v.gas_limit_                 = as_u64 (next_required(it));
    parse_to(v, next_required(it), v.to_, v.to_present_);
    v.value_                     = as_u256(next_required(it));
    v.data_                      = as_bytes(next_required(it));
    v.access_list_rlp_           = as_list_raw(next_required(it));
    v.max_fee_per_blob_gas_      = as_u256(next_required(it));
    v.blob_versioned_hashes_rlp_ = as_list_raw(next_required(it));
    v.v_or_y_parity_             = as_u64 (next_required(it));
    v.r_                         = as_u256(next_required(it));
    v.s_                         = as_u256(next_required(it));
    require_end(it);
}

void Transactions::parse_set_code(View& v, std::span<const uint8_t> outer_payload) {
    ListIter it{outer_payload};
    v.chain_id_                 = as_u64 (next_required(it));
    v.nonce_                    = as_u64 (next_required(it));
    v.max_priority_fee_per_gas_ = as_u256(next_required(it));
    v.max_fee_per_gas_          = as_u256(next_required(it));
    v.gas_limit_                = as_u64 (next_required(it));
    parse_to(v, next_required(it), v.to_, v.to_present_);
    v.value_                    = as_u256(next_required(it));
    v.data_                     = as_bytes(next_required(it));
    v.access_list_rlp_          = as_list_raw(next_required(it));
    v.authorization_list_rlp_   = as_list_raw(next_required(it));
    v.v_or_y_parity_            = as_u64 (next_required(it));
    v.r_                        = as_u256(next_required(it));
    v.s_                        = as_u256(next_required(it));
    require_end(it);
}

// EIP-7873 / Osaka: same field order as SetCode, with `initcodes`
// replacing `authorization_list`. `initcodes` is an RLP list of byte
// strings — each entry is one raw initcode addressable by hash via the
// TXCREATE opcode.
void Transactions::parse_osaka(View& v, std::span<const uint8_t> outer_payload) {
    ListIter it{outer_payload};
    v.chain_id_                 = as_u64 (next_required(it));
    v.nonce_                    = as_u64 (next_required(it));
    v.max_priority_fee_per_gas_ = as_u256(next_required(it));
    v.max_fee_per_gas_          = as_u256(next_required(it));
    v.gas_limit_                = as_u64 (next_required(it));
    parse_to(v, next_required(it), v.to_, v.to_present_);
    v.value_                    = as_u256(next_required(it));
    v.data_                     = as_bytes(next_required(it));
    v.access_list_rlp_          = as_list_raw(next_required(it));
    v.initcodes_rlp_            = as_list_raw(next_required(it));
    v.v_or_y_parity_            = as_u64 (next_required(it));
    v.r_                        = as_u256(next_required(it));
    v.s_                        = as_u256(next_required(it));
    require_end(it);
}

// EIP-2930 access list: a list of entries [address(20 B), [storageKey(32 B)…]].
// The outer tx list is decoded strictly (require_end); this enforces the SAME
// strictness on each access-list entry — exact 2-field arity, 20-byte address,
// 32-byte keys, no trailing fields — so a tx the rest of the network rejects
// (extra entry field, wrong-width key) is not silently accepted by the guest.
// Mirrors execution-specs `Access` (decode_to) and alloy-eip2930. The 20/32-byte
// checks previously lived only in `pre_warm_for_tx`; validating here makes every
// downstream reader (intrinsic gas + warm-up) inherit a pre-validated list.
void validate_access_list(std::span<const uint8_t> access_list_rlp) {
    const Item outer = rlp::decode_item(access_list_rlp);
    if (outer.kind != ItemKind::List) {
        fatal("Transactions: access_list is not an RLP list");
    }
    ListIter it{outer.payload};
    while (it.has_next()) {
        const Item entry = it.next();
        if (entry.kind != ItemKind::List) {
            fatal("Transactions: access_list entry is not a list");
        }
        ListIter eit{entry.payload};
        const Item addr = next_required(eit);
        if (addr.kind != ItemKind::String || addr.payload.size() != 20) {
            fatal("Transactions: access_list address must be 20 bytes");
        }
        const Item keys = next_required(eit);
        if (keys.kind != ItemKind::List) {
            fatal("Transactions: access_list keys field is not a list");
        }
        ListIter kit{keys.payload};
        while (kit.has_next()) {
            const Item k = kit.next();
            if (k.kind != ItemKind::String || k.payload.size() != 32) {
                fatal("Transactions: access_list storage key must be 32 bytes");
            }
        }
        if (eit.has_next()) {
            fatal("Transactions: access_list entry has trailing fields");
        }
    }
}

// EIP-7702 authorization list: a list of 6-tuples
//   [chain_id, address(20 B), nonce, y_parity, r, s].
// Validate structure strictly in the constructor, before execution, so a tuple
// with extra fields or a non-canonical / wrong-width field (which every other
// client rejects) cannot later be applied. Structural failure rejects the block;
// SEMANTIC validity (y_parity ∈ {0,1}, chain/nonce match, signature recovery) is
// still decided per-authorization at execution and only skips that authorization,
// per the spec. Validating in the constructor also means a tuple after a
// runtime-OOG (Amsterdam stops applying there) is still structurally checked.
// Returns the entry count (used for the 25000-per-authorization intrinsic gas).
// Mirrors execution-specs `Authorization` (exact arity) and alloy.
size_t validate_authorization_list(std::span<const uint8_t> auth_list_rlp) {
    const Item outer = rlp::decode_item(auth_list_rlp);
    if (outer.kind != ItemKind::List) {
        fatal("Transactions: authorization_list not an RLP list");
    }
    size_t n = 0;
    ListIter it{outer.payload};
    while (it.has_next()) {
        const Item tuple = it.next();
        if (tuple.kind != ItemKind::List) {
            fatal("Transactions: authorization tuple is not a list");
        }
        ListIter tit{tuple.payload};
        (void)as_u256(next_required(tit));          // chain_id: canonical, <=32 B
        const Item addr = next_required(tit);        // address: exactly 20 bytes
        if (addr.kind != ItemKind::String || addr.payload.size() != 20) {
            fatal("Transactions: authorization address must be 20 bytes");
        }
        (void)as_u64(next_required(tit));            // nonce: canonical U64
        const Item parity = next_required(tit);      // y_parity: canonical, <=1 byte
        if (parity.kind != ItemKind::String || parity.payload.size() > 1) {
            fatal("Transactions: authorization y_parity must be <=1 byte");
        }
        (void)as_u64(parity);                        // reject non-canonical 0x00
        (void)as_u256(next_required(tit));           // r: canonical U256
        (void)as_u256(next_required(tit));           // s: canonical U256
        if (tit.has_next()) {
            fatal("Transactions: authorization tuple has trailing fields");
        }
        ++n;
    }
    return n;
}

// ============================================================================
// Constructor — for each tx: read u64 envelope_size + envelope bytes + pad.
// Decode every field, recover the sender from the signature.
// ============================================================================

Transactions::Transactions(const uint8_t*& cursor) {
    const uint64_t count = read_u64_le(cursor);
    // Each tx needs at least its 8-byte envelope-size prefix; a count beyond
    // that many remaining bytes is malformed — reject before the reserve and
    // loop (bounds checks, see zeg/stream.hpp).
    if (count > stream_remaining(cursor) / 8) {
        fatal("Transactions: count exceeds input size");
    }
    views_.reserve(count);

    // Builds the canonical transactions trie alongside the per-tx
    // parsing — the value at each leaf is the wire envelope verbatim
    // (`type_byte || rlp` for typed, raw RLP list for legacy). Root
    // hashed once at the end of the loop into transactions_root_.
    MerklePatriciaTrie trie;

    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t env_size = read_u64_le(cursor);

        const uint8_t* env = cursor;
        advance_checked(cursor, env_size);
        align_to_u64(cursor, env_size);

        if (env_size == 0) {
            fatal("Transactions: empty tx envelope");
        }

        View v;
        const uint8_t lead = env[0];
        if (lead >= 0xc0)      v.type_ = Type::Legacy;       // RLP list header
        else if (lead == 0x01) v.type_ = Type::AccessList;
        else if (lead == 0x02) v.type_ = Type::DynamicFee;
        else if (lead == 0x03) v.type_ = Type::Blob;
        else if (lead == 0x04) v.type_ = Type::SetCode;
        else if (lead == 0x05) v.type_ = Type::Osaka;
        else fatal("Transactions: unknown envelope first byte");

        // Strip the 1-byte type tag for typed txs; legacy txs already
        // start at the outer list header.
        BytesView whole{env, env_size};
        if (v.type_ != Type::Legacy) {
            whole = BytesView{whole.data() + 1, whole.size() - 1};
        }
        const Item outer = rlp::decode_item(whole);
        if (outer.kind != ItemKind::List) {
            fatal("Transactions: outer envelope item is not a list");
        }
        // The decoded outer list must cover the whole envelope — no trailing
        // bytes after it. Trailing bytes make the envelope non-canonical (a
        // block the network rejects) even though the signed fields recover the
        // same sender.
        if (outer.raw.size() != whole.size()) {
            fatal("Transactions: trailing bytes after tx envelope");
        }

        switch (v.type_) {
            case Type::Legacy:     parse_legacy     (v, outer.payload); break;
            case Type::AccessList: parse_access_list(v, outer.payload); break;
            case Type::DynamicFee: parse_dynamic_fee(v, outer.payload); break;
            case Type::Blob:       parse_blob       (v, outer.payload); break;
            case Type::SetCode:    parse_set_code   (v, outer.payload); break;
            case Type::Osaka:      parse_osaka      (v, outer.payload); break;
        }

        // Every typed tx carries an access list; validate its inner entries
        // strictly here (the outer tx list is already strict). Legacy has none.
        if (v.type_ != Type::Legacy) {
            validate_access_list(v.access_list_rlp_);
        }

        // For Type 4 (SetCode / EIP-7702): structurally validate every auth
        // tuple (exact arity + canonical/width-checked fields) and count them
        // (the intrinsic-gas calculation charges 25000 per authorization).
        if (v.type_ == Type::SetCode) {
            v.num_authorizations_ = validate_authorization_list(v.authorization_list_rlp_);
        }

        v.envelope_         = {env, env_size};
        v.transaction_hash_ = keccak256_bytes32(env, env_size);
        v.sender_           = recover_sender(v);

        rlp_list_payload_size_ +=
            v.type_ == Type::Legacy ? env_size : rlp::item_size(env_size);

        // MPT leaf: RLP(tx_index) → wire envelope verbatim.
        trie.insert(rlp::encode_u64(i),
                    std::vector<uint8_t>(env, env + env_size));

        views_.push_back(std::move(v));
    }

    transactions_root_ = trie.root_hash();
}

} // namespace zeg

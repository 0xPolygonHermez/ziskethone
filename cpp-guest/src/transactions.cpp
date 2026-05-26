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
// Signature verification + sender recovery (file-local).
//
// ZisK's secp256k1_ecdsa_verify takes 256-bit values as 4-limb arrays
// of native uint64 (limb[0] = least significant 64 bits, matching the
// `mpz_import(..., -1, 8, -1, ...)` decoding in lib-c's array2fe).
// Inputs from this guest are big-endian (Ethereum convention), so each
// 32-byte value is byte-reversed limb-by-limb on the way in.
// ============================================================================

// Read 8 big-endian bytes into a native uint64.
uint64_t be_load64(const uint8_t* p) {
    return (uint64_t(p[0]) << 56) | (uint64_t(p[1]) << 48)
         | (uint64_t(p[2]) << 40) | (uint64_t(p[3]) << 32)
         | (uint64_t(p[4]) << 24) | (uint64_t(p[5]) << 16)
         | (uint64_t(p[6]) <<  8) |  uint64_t(p[7]);
}

// Convert a 32-byte big-endian integer into a 4-limb little-endian-ordered
// array (limbs[0] = least significant 64 bits).
void be32_to_limbs(const uint8_t* be32, uint64_t limbs[4]) {
    limbs[0] = be_load64(be32 + 24);
    limbs[1] = be_load64(be32 + 16);
    limbs[2] = be_load64(be32 +  8);
    limbs[3] = be_load64(be32 +  0);
}

// secp256k1 curve order n in the same limb layout (LE-ordered, native
// limbs). Used to handle the rare case `result.x >= n` in the final
// ECDSA check.
constexpr uint64_t SECP256K1_N[4] = {
    0xBFD25E8CD0364141ULL,
    0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL,
    0xFFFFFFFFFFFFFFFFULL,
};

// 256-bit subtraction: out = a - b. Returns the final borrow (1 if
// a < b, else 0).
unsigned sub_256(const uint64_t a[4], const uint64_t b[4], uint64_t out[4]) {
    unsigned borrow = 0;
    for (int i = 0; i < 4; ++i) {
        const uint64_t ai = a[i];
        const uint64_t bi = b[i];
        const uint64_t di = ai - bi - borrow;
        borrow = (ai < bi + borrow) || (bi == ~uint64_t{0} && borrow) ? 1 : 0;
        out[i] = di;
    }
    return borrow;
}

bool limbs_eq(const uint64_t a[4], const uint64_t b[4]) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

// Verify the (r, s) signature in `v` against `pubkey` (64 raw bytes,
// x || y, BE) over the signing hash of `v`. Returns the recovered
// sender address on success; aborts via zeg::fatal on any failure.
evmc::address verify_and_recover_sender(const Transactions::View& v,
                                        const uint8_t* pubkey) {
    const evmc::bytes32 z = compute_signing_hash(v);

    uint64_t pk[8];
    be32_to_limbs(pubkey,      pk);       // pk_x
    be32_to_limbs(pubkey + 32, pk + 4);   // pk_y

    uint64_t z_limbs[4];
    uint64_t r_limbs[4];
    uint64_t s_limbs[4];
    be32_to_limbs(z.bytes,         z_limbs);
    be32_to_limbs(v.r().bytes,     r_limbs);
    be32_to_limbs(v.s().bytes,     s_limbs);

    uint64_t result[8];
    secp256k1_ecdsa_verify(pk, z_limbs, r_limbs, s_limbs, result);

    // ECDSA: signature is valid iff (result.x mod n) == r. result.x is
    // mod p; it may exceed n by < n (since p < 2n for secp256k1), so
    // at most one conditional subtraction is needed.
    const uint64_t* rx = result;  // first 4 limbs = x
    if (!limbs_eq(rx, r_limbs)) {
        uint64_t reduced[4];
        const unsigned borrow = sub_256(rx, SECP256K1_N, reduced);
        if (borrow != 0 || !limbs_eq(reduced, r_limbs)) {
            fatal("Transactions: secp256k1 signature verification failed");
        }
    }

    // Sender = keccak256(pubkey_64_bytes)[12:32]. No 0x04 SEC1 prefix.
    const evmc::bytes32 ph = keccak256_bytes32(pubkey, 64);
    evmc::address sender;
    std::memcpy(sender.bytes, ph.bytes + 12, 20);
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

std::span<const uint8_t> Transactions::View::auth_pubkey(size_t i) const {
    if (i >= num_auth_pubkeys_) {
        fatal("Transactions::View::auth_pubkey: index out of range");
    }
    return std::span<const uint8_t>{auth_pubkeys_ + i * 64, 64};
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
}

// ============================================================================
// Constructor — for each tx: read u64 envelope_size + 64 pubkey bytes +
// envelope bytes + pad. Decode every field, verify signature, derive
// sender.
// ============================================================================

Transactions::Transactions(const uint8_t*& cursor) {
    const uint64_t count = read_u64_le(cursor);
    views_.reserve(count);

    // Builds the canonical transactions trie alongside the per-tx
    // parsing — the value at each leaf is the wire envelope verbatim
    // (`type_byte || rlp` for typed, raw RLP list for legacy). Root
    // hashed once at the end of the loop into transactions_root_.
    MerklePatriciaTrie trie;

    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t env_size = read_u64_le(cursor);

        // Prover-supplied sender pubkey. Starts at offset 8 within the
        // record so naturally 8-byte aligned; 64 bytes is itself a
        // multiple of 8.
        const uint8_t* pubkey = cursor;
        cursor += 64;

        const uint8_t* env = cursor;
        cursor += env_size;
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

        switch (v.type_) {
            case Type::Legacy:     parse_legacy     (v, outer.payload); break;
            case Type::AccessList: parse_access_list(v, outer.payload); break;
            case Type::DynamicFee: parse_dynamic_fee(v, outer.payload); break;
            case Type::Blob:       parse_blob       (v, outer.payload); break;
            case Type::SetCode:    parse_set_code   (v, outer.payload); break;
            case Type::Osaka:      parse_osaka      (v, outer.payload); break;
        }

        // For Type 4 (SetCode / EIP-7702): the prover supplies one
        // uncompressed pubkey (64 B, x || y, BE) per authorization in
        // the auth list. Count the auth entries we just parsed and
        // read that many pubkeys from the stream. 64 B is already
        // 8-aligned so no extra padding is needed.
        if (v.type_ == Type::SetCode) {
            const Item auth_outer = rlp::decode_item(v.authorization_list_rlp_);
            if (auth_outer.kind != ItemKind::List) {
                fatal("Transactions: authorization_list not an RLP list");
            }
            size_t n = 0;
            ListIter ait{auth_outer.payload};
            while (ait.has_next()) { (void)ait.next(); ++n; }
            v.auth_pubkeys_     = cursor;
            v.num_auth_pubkeys_ = n;
            cursor += n * 64;
        }

        v.transaction_hash_ = keccak256_bytes32(env, env_size);
        v.sender_           = verify_and_recover_sender(v, pubkey);

        // MPT leaf: RLP(tx_index) → wire envelope verbatim.
        trie.insert(rlp::encode_u64(i),
                    std::vector<uint8_t>(env, env + env_size));

        views_.push_back(std::move(v));
    }

    transactions_root_ = trie.root_hash();
}

} // namespace zeg

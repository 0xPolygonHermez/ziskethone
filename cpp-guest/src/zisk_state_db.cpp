#include "zeg/zisk_state_db.hpp"

#include <cstring>
#include <vector>

#include <evmone/evmone.h>  // evmc_create_evmone for the owned VM instance
#include <intx/intx.hpp>    // 256-bit add for selfdestruct balance transfer

#include "zeg/config.hpp"
#include "zeg/fatal.hpp"
#include "zeg/keccak.hpp"
#include "zeg/mpt.hpp"
#include "zeg/rlp.hpp"
#include "zeg/sha256.hpp"
#include "zeg/zisk_crypto.hpp"  // secp256k1_ecdsa_verify (EIP-7702 auth signer)

namespace zeg {

namespace {

// keccak256 of the empty byte string. An account whose code_hash equals
// this is considered to have no code (per Yellow Paper §4.1).
constexpr evmc::bytes32 EMPTY_CODE_HASH{{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
}};

// EVMC SSTORE status code per the EVMC spec (full 9-state table). The
// inputs are: `original` = slot value at the start of the current tx
// (EIP-2200), `current` = value right before this write, `new_value`
// = value being written.
evmc_storage_status compute_storage_status(const evmc::bytes32& original,
                                           const evmc::bytes32& current,
                                           const evmc::bytes32& new_value) {
    constexpr evmc::bytes32 zero{};

    if (new_value == current) {
        return EVMC_STORAGE_ASSIGNED;
    }
    if (original == current) {
        // First write in this tx.
        if (original  == zero) return EVMC_STORAGE_ADDED;
        if (new_value == zero) return EVMC_STORAGE_DELETED;
        return EVMC_STORAGE_MODIFIED;
    }
    // Already dirtied in this tx (current != original).
    if (original != zero && current == zero) {
        // X -> 0 -> ?
        return (new_value == original) ? EVMC_STORAGE_DELETED_RESTORED
                                       : EVMC_STORAGE_DELETED_ADDED;
    }
    if (original != zero && new_value == zero) {
        return EVMC_STORAGE_MODIFIED_DELETED;
    }
    if (original == zero && new_value == zero) {
        return EVMC_STORAGE_ADDED_DELETED;  // 0 -> X -> 0
    }
    if (original == new_value) {
        return EVMC_STORAGE_MODIFIED_RESTORED;
    }
    return EVMC_STORAGE_ASSIGNED;  // X -> Y -> Z fallback
}

// CREATE address derivation (Yellow Paper §7):
//   address = keccak256(rlp([sender, sender_nonce]))[12:32]
// `sender_nonce` is the value BEFORE the create-time increment.
evmc::address compute_create_address(const evmc::address& sender,
                                     uint64_t sender_nonce) {
    using rlp::BytesView;
    const auto sender_rlp = rlp::encode(BytesView{sender.bytes, 20});
    const auto nonce_rlp  = rlp::encode_u64(sender_nonce);
    const auto list_rlp   = rlp::encode_list({
        BytesView{sender_rlp.data(), sender_rlp.size()},
        BytesView{nonce_rlp.data(),  nonce_rlp.size()},
    });
    const auto h = keccak256_bytes32(list_rlp.data(), list_rlp.size());
    evmc::address addr{};
    std::memcpy(addr.bytes, h.bytes + 12, 20);
    return addr;
}

// CREATE2 address derivation (EIP-1014; same formula for EOFCREATE,
// EIP-7620, just with the init container's bytes instead of the
// init-code bytes — the EVM hands us the appropriate bytes either way):
//   address = keccak256(0xff || sender || salt || keccak256(init))[12:32]
evmc::address compute_create2_address(const evmc::address&    sender,
                                      const evmc::bytes32&    salt,
                                      const uint8_t*          init_code,
                                      size_t                  init_code_size) {
    const auto init_hash = keccak256_bytes32(init_code, init_code_size);
    uint8_t buf[1 + 20 + 32 + 32];
    buf[0] = 0xff;
    std::memcpy(buf + 1,  sender.bytes,    20);
    std::memcpy(buf + 21, salt.bytes,      32);
    std::memcpy(buf + 53, init_hash.bytes, 32);
    const auto h = keccak256_bytes32(buf, sizeof(buf));
    evmc::address addr{};
    std::memcpy(addr.bytes, h.bytes + 12, 20);
    return addr;
}

// Tx intrinsic gas (Yellow Paper §6.2):
//   base
//   + sum over calldata: 4 (zero byte) or 16 (non-zero, EIP-2028)
//   + EIP-3860 initcode word cost for creates
//   + EIP-2930 access-list cost: 2400/addr + 1900/storage-key
//   + EIP-7702 auth-list cost: PER_EMPTY_ACCOUNT_COST per auth.
//     Slight over-charge for auths whose signer already had a
//     delegation (spec allows a 12500 refund per such auth); we don't
//     compute the refund — would require running the per-auth recovery
//     here just to check signer state, doubling that work.
int64_t compute_intrinsic_gas(const Transactions::View& tx) {
    using TxType = Transactions::Type;

    int64_t gas = (tx.to() == nullptr) ? 53000 : 21000;

    for (uint8_t b : tx.data()) {
        gas += (b == 0) ? 4 : 16;
    }
    if (tx.to() == nullptr) {
        gas += static_cast<int64_t>((tx.data().size() + 31) / 32) * 2;
    }

    // EIP-2930 access list. Typed txs always carry one (possibly
    // empty, i.e. just `0xc0`); legacy txs don't.
    if (tx.type() != TxType::Legacy) {
        const auto outer = rlp::decode_item(tx.access_list_rlp());
        if (outer.kind != rlp::ItemKind::List) {
            fatal("access_list is not an RLP list");
        }
        rlp::ListIter it{outer.payload};
        while (it.has_next()) {
            const auto entry = it.next();
            if (entry.kind != rlp::ItemKind::List) {
                fatal("access_list entry is not an RLP list");
            }
            rlp::ListIter eit{entry.payload};
            if (!eit.has_next()) fatal("access_list entry missing address");
            (void)eit.next();
            gas += 2400;  // ACCESS_LIST_ADDRESS_COST
            if (!eit.has_next()) fatal("access_list entry missing keys");
            const auto keys = eit.next();
            if (keys.kind != rlp::ItemKind::List) {
                fatal("access_list storage-keys field is not an RLP list");
            }
            rlp::ListIter kit{keys.payload};
            while (kit.has_next()) {
                (void)kit.next();
                gas += 1900;  // ACCESS_LIST_STORAGE_KEY_COST
            }
        }
    }

    // EIP-7702 authorization list. View already counted entries while
    // reading the prover-supplied auth pubkeys — reuse that count
    // instead of re-walking the RLP.
    if (tx.type() == TxType::SetCode) {
        gas += 25000 * static_cast<int64_t>(tx.num_auth_pubkeys());
    }

    return gas;
}

// EIP-4844 fake exponential. Reference Python:
//   def fake_exponential(factor, numerator, denominator):
//       output = 0
//       numerator_accum = factor * denominator
//       i = 1
//       while numerator_accum > 0:
//           output += numerator_accum
//           numerator_accum = (numerator_accum * numerator) //
//                             (denominator * i)
//           i += 1
//       return output // denominator
// All math fits in 256 bits for plausible inputs (excess_blob_gas
// stays in a u64-range).
intx::uint256 fake_exponential(uint64_t factor,
                               uint64_t numerator,
                               uint64_t denominator) {
    const intx::uint256 num_u   = intx::uint256{numerator};
    const intx::uint256 denom_u = intx::uint256{denominator};
    intx::uint256 output    = 0;
    intx::uint256 num_accum = intx::uint256{factor} * denom_u;
    intx::uint256 i         = 1;
    while (num_accum > 0) {
        output    += num_accum;
        num_accum = (num_accum * num_u) / (denom_u * i);
        i        += 1;
    }
    return output / denom_u;
}

// EIP-4844 constants.
constexpr uint64_t kMinBaseFeePerBlobGas      = 1;
constexpr uint64_t kBlobBaseFeeUpdateFraction = 3338477;
constexpr uint64_t kGasPerBlob                = 131072;

// Pre/post-block system-call constants. The synthetic system address
// is the caller for every system call (EIP-4788, EIP-2935, EIP-7002,
// EIP-7251); each predeploy contract has a Pectra-mandated fixed
// address. The 30M gas limit comes from EIP-4788 §4.
constexpr evmc::address kSystemAddress{{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe,
}};
constexpr evmc::address kBeaconRootsAddress{{
    0x00, 0x0F, 0x3d, 0xf6, 0xD7, 0x32, 0x80, 0x7E,
    0xf1, 0x31, 0x9f, 0xB7, 0xB8, 0xbB, 0x85, 0x22,
    0xd0, 0xBe, 0xac, 0x02,
}};
constexpr evmc::address kHistoryStorageAddress{{
    0x00, 0x00, 0xF9, 0x08, 0x27, 0xF1, 0xC5, 0x3a,
    0x10, 0xcb, 0x7A, 0x02, 0x33, 0x5B, 0x17, 0x53,
    0x20, 0x00, 0x29, 0x35,
}};
// EIP-7002: withdrawal-requests predeploy. Dequeues pending withdrawal
// requests when called with empty calldata. Each record is 76 bytes:
// 20 source_address || 48 validator_pubkey || 8 amount_gwei (BE).
constexpr evmc::address kWithdrawalRequestsAddress{{
    0x00, 0x00, 0x09, 0x61, 0xEf, 0x48, 0x0E, 0xb5,
    0x5e, 0x80, 0xD1, 0x9a, 0xd8, 0x35, 0x79, 0xA6,
    0x4c, 0x00, 0x70, 0x02,
}};
// EIP-7251: consolidation-requests predeploy. Same shape as 7002;
// each record is 116 bytes: 20 source_address || 48 source_pubkey ||
// 48 target_pubkey.
constexpr evmc::address kConsolidationRequestsAddress{{
    0x00, 0x00, 0xBB, 0xdD, 0xc7, 0xCE, 0x48, 0x86,
    0x42, 0xfb, 0x57, 0x9F, 0x8B, 0x00, 0xf3, 0xa5,
    0x90, 0x00, 0x72, 0x51,
}};
constexpr int64_t kSystemCallGas = 30'000'000;

// EIP-6110: deposits are extracted from event logs emitted by the
// beacon-deposit contract during regular tx execution (no system
// call). Address is the canonical mainnet value; testnets that use a
// different deposit contract will need this configurable.
constexpr evmc::address kDepositContractAddress{{
    0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40,
    0x35, 0x6c, 0xBB, 0x83, 0x9C, 0xbe, 0x05, 0x30,
    0x3d, 0x77, 0x05, 0xFa,
}};

// EIP-7685 request type bytes.
constexpr uint8_t kRequestTypeDeposit       = 0x00;
constexpr uint8_t kRequestTypeWithdrawal    = 0x01;
constexpr uint8_t kRequestTypeConsolidation = 0x02;

// Read a 32-byte big-endian uint at `p` as a size_t. Aborts via fatal
// if the value doesn't fit (upper 24 bytes non-zero). Used for ABI
// offsets/lengths.
size_t read_abi_uint32be_as_size(const uint8_t* p) {
    for (size_t i = 0; i < 24; ++i) {
        if (p[i] != 0) {
            fatal("DepositEvent ABI: integer field overflows size_t");
        }
    }
    size_t v = 0;
    for (size_t i = 24; i < 32; ++i) {
        v = (v << 8) | p[i];
    }
    return v;
}

// Read the i-th dynamic-`bytes` field from a Solidity-encoded event
// payload that consists entirely of `bytes` parameters. Returns
// (data_ptr, length). Aborts via fatal on truncation / corruption.
struct AbiBytesField { const uint8_t* data; size_t length; };
AbiBytesField abi_read_bytes_field(const uint8_t* data, size_t data_size,
                                   size_t field_index) {
    const size_t off_pos = field_index * 32;
    if (off_pos + 32 > data_size) {
        fatal("DepositEvent ABI: offset slot out of bounds");
    }
    const size_t offset = read_abi_uint32be_as_size(data + off_pos);
    if (offset + 32 > data_size) {
        fatal("DepositEvent ABI: length slot out of bounds");
    }
    const size_t length = read_abi_uint32be_as_size(data + offset);
    if (offset + 32 + length > data_size) {
        fatal("DepositEvent ABI: bytes payload out of bounds");
    }
    return AbiBytesField{data + offset + 32, length};
}

// Add `data[0..size]` to a 2048-bit bloom filter per Yellow Paper
// §4.4.2: three 11-bit indices come from byte-pairs of keccak256(data),
// bits packed big-endian inside the 256-byte buffer.
void bloom_add(std::array<uint8_t, 256>& bloom,
               const uint8_t* data, size_t size) {
    const evmc::bytes32 h = keccak256_bytes32(data, size);
    for (int i = 0; i < 3; ++i) {
        const uint16_t pair     =
            (uint16_t(h.bytes[i * 2]) << 8) | h.bytes[i * 2 + 1];
        const uint16_t p        = pair & 0x07FF;            // [0, 2047]
        const size_t   byte_idx = 256 - 1 - (p >> 3);
        const uint8_t  bit_mask = uint8_t(1) << (p & 0x07);
        bloom[byte_idx] |= bit_mask;
    }
}

// ---------- secp256k1 verify+recover (used by EIP-7702 auth list) ----------

uint64_t be_load64(const uint8_t* p) {
    return (uint64_t(p[0]) << 56) | (uint64_t(p[1]) << 48)
         | (uint64_t(p[2]) << 40) | (uint64_t(p[3]) << 32)
         | (uint64_t(p[4]) << 24) | (uint64_t(p[5]) << 16)
         | (uint64_t(p[6]) <<  8) |  uint64_t(p[7]);
}

void be32_to_limbs(const uint8_t* be32, uint64_t limbs[4]) {
    limbs[0] = be_load64(be32 + 24);
    limbs[1] = be_load64(be32 + 16);
    limbs[2] = be_load64(be32 +  8);
    limbs[3] = be_load64(be32 +  0);
}

constexpr uint64_t kSecp256k1N[4] = {
    0xBFD25E8CD0364141ULL,
    0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL,
    0xFFFFFFFFFFFFFFFFULL,
};

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

// Verify ECDSA(secp256k1) signature against `pubkey` (64 B, x || y, BE)
// and return signer = keccak256(pubkey)[12:]. Aborts via fatal on any
// verification failure.
evmc::address verify_signature_and_get_signer(
        const uint8_t*         pubkey,
        const evmc::bytes32&   signing_hash,
        const evmc::uint256be& r,
        const evmc::uint256be& s) {
    uint64_t pk[8];
    be32_to_limbs(pubkey,      pk);
    be32_to_limbs(pubkey + 32, pk + 4);

    uint64_t z_limbs[4], r_limbs[4], s_limbs[4];
    be32_to_limbs(signing_hash.bytes, z_limbs);
    be32_to_limbs(r.bytes,            r_limbs);
    be32_to_limbs(s.bytes,            s_limbs);

    uint64_t result[8];
    secp256k1_ecdsa_verify(pk, z_limbs, r_limbs, s_limbs, result);

    // result.x mod n == r (mod n). result.x < p < 2n for secp256k1,
    // so at most one conditional subtraction is needed.
    const uint64_t* rx = result;
    if (!limbs_eq(rx, r_limbs)) {
        uint64_t reduced[4];
        const unsigned borrow = sub_256(rx, kSecp256k1N, reduced);
        if (borrow != 0 || !limbs_eq(reduced, r_limbs)) {
            fatal("ECDSA signature verification failed");
        }
    }

    const evmc::bytes32 ph = keccak256_bytes32(pubkey, 64);
    evmc::address signer{};
    std::memcpy(signer.bytes, ph.bytes + 12, 20);
    return signer;
}

// Wrap an already-concatenated payload of pre-encoded RLP items as
// an RLP list. `rlp::encode_list`'s initializer_list overload is
// compile-time-sized; this helper is its runtime-sized sibling.
rlp::Bytes wrap_rlp_list(const rlp::Bytes& payload) {
    rlp::Bytes out;
    if (payload.size() <= 55) {
        out.reserve(1 + payload.size());
        out.push_back(static_cast<uint8_t>(0xc0 + payload.size()));
    } else {
        size_t l = payload.size();
        uint8_t nbytes = 0;
        for (size_t x = l; x > 0; x >>= 8) ++nbytes;
        out.reserve(1 + nbytes + payload.size());
        out.push_back(static_cast<uint8_t>(0xf7 + nbytes));
        for (int8_t i = nbytes - 1; i >= 0; --i) {
            out.push_back(static_cast<uint8_t>(l >> (8 * i)));
        }
    }
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// Canonical receipt encoding per Yellow Paper §4.3.1:
//   Legacy:  rlp([status, cum_gas_used, logs_bloom, logs])
//   Typed:   type_byte || rlp([…same fields…])
// where each log is RLP-encoded as [address, [topics…], data].
std::vector<uint8_t> encode_receipt(const ZiskStateDB::TxReceipt& r) {
    using rlp::BytesView;

    // Build the outer logs list: concat each log's RLP, then wrap.
    rlp::Bytes logs_payload;
    for (const auto& log : r.logs) {
        const auto addr_rlp = rlp::encode(BytesView{log.address.bytes, 20});

        // Topics: variable-count list of 32-byte strings.
        rlp::Bytes topics_payload;
        for (const auto& t : log.topics) {
            const auto t_rlp = rlp::encode(BytesView{t.bytes, 32});
            topics_payload.insert(topics_payload.end(),
                                  t_rlp.begin(), t_rlp.end());
        }
        const auto topics_list = wrap_rlp_list(topics_payload);

        const auto data_rlp = rlp::encode(BytesView{log.data.data(),
                                                    log.data.size()});

        const auto log_rlp = rlp::encode_list({
            BytesView{addr_rlp},
            BytesView{topics_list},
            BytesView{data_rlp},
        });
        logs_payload.insert(logs_payload.end(),
                            log_rlp.begin(), log_rlp.end());
    }
    const auto logs_list = wrap_rlp_list(logs_payload);

    const auto status_rlp  = rlp::encode_u64(r.status ? 1u : 0u);
    const auto cum_gas_rlp = rlp::encode_u64(r.cumulative_gas_used);
    const auto bloom_rlp   = rlp::encode(BytesView{r.logs_bloom.data(),
                                                   r.logs_bloom.size()});

    const auto body = rlp::encode_list({
        BytesView{status_rlp},
        BytesView{cum_gas_rlp},
        BytesView{bloom_rlp},
        BytesView{logs_list},
    });

    if (r.tx_type == Transactions::Type::Legacy) {
        return std::vector<uint8_t>(body.begin(), body.end());
    }
    std::vector<uint8_t> out;
    out.reserve(1 + body.size());
    out.push_back(static_cast<uint8_t>(r.tx_type));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

} // namespace

// ===== Constructor =====

ZiskStateDB::ZiskStateDB(Accounts&             accounts,
                         const ConsensusInfo&  consensus,
                         const Contracts&      contracts,
                         const PreviousBlocks& previous_blocks,
                         Storages&             storages)
    : accounts_(accounts),
      consensus_(consensus),
      contracts_(contracts),
      previous_blocks_(previous_blocks),
      storages_(storages),
      vm_(evmc_create_evmone()) {}

// ===== evmc::Host pass-through implementations =====

bool ZiskStateDB::account_exists(const evmc::address& addr) const noexcept {
    // Stateless witness model: every queried account must be in the
    // input. `index_of` aborts via zeg::fatal if not — the prover bug
    // surfaces immediately. "Exists" semantically = non-empty (nonzero
    // balance OR nonce OR non-empty code).
    const size_t idx = accounts_.index_of(addr);
    if (accounts_.nonce_at(idx) != 0) {
        return true;
    }
    if (accounts_.code_hash_at(idx) != EMPTY_CODE_HASH) {
        return true;
    }
    const auto bal = accounts_.balance_at(idx);
    for (uint8_t b : bal.bytes) {
        if (b != 0) {
            return true;
        }
    }
    return false;
}

evmc::bytes32 ZiskStateDB::get_storage(const evmc::address& addr,
                                       const evmc::bytes32& key) const noexcept {
    // `storages_.value(...)` touches the slot for tx_counter_ (snapshots
    // tx_original on first access, marks warm). The const_cast is safe:
    // mods_ is logically mutable scratch — evmc::Host::get_storage is
    // const-by-interface but the per-tx tracking has to happen here.
    return const_cast<Storages&>(storages_).value(addr, key, tx_counter_);
}

evmc_storage_status ZiskStateDB::set_storage(const evmc::address& addr,
                                             const evmc::bytes32& key,
                                             const evmc::bytes32& value) noexcept {
    // No explicit mark_touched_at here: on Berlin+ revisions evmone
    // always calls access_storage(addr, key) before set_storage, and
    // our access_storage already does the snapshot. So by the time
    // we read tx_original_at below the per-tx-original is in place.
    const size_t idx = storages_.index_of(addr, key);

    const auto& original = storages_.tx_original_at(idx);
    const auto  current  = storages_.value_at(idx);

    journal_.log_storage(idx, current);
    storages_.set_value_at(idx, value);

    return compute_storage_status(original, current, value);
}

evmc::uint256be ZiskStateDB::get_balance(const evmc::address& addr) const noexcept {
    // const_cast: the per-tx warm-touch mutates accounts_.mods_,
    // which is logically scratch state. Same pattern as get_storage.
    return const_cast<Accounts&>(accounts_).balance(addr, tx_counter_);
}

evmc::bytes32 ZiskStateDB::get_code_hash(const evmc::address& addr) const noexcept {
    return const_cast<Accounts&>(accounts_).code_hash(addr, tx_counter_);
}

size_t ZiskStateDB::get_code_size(const evmc::address& addr) const noexcept {
    const auto hash = const_cast<Accounts&>(accounts_).code_hash(addr, tx_counter_);
    if (hash == EMPTY_CODE_HASH) {
        return 0;
    }
    return static_cast<size_t>(contracts_.by_hash(hash).code_size);
}

size_t ZiskStateDB::copy_code(const evmc::address& addr,
                              size_t offset,
                              uint8_t* buffer,
                              size_t buffer_size) const noexcept {
    const auto hash = const_cast<Accounts&>(accounts_).code_hash(addr, tx_counter_);
    if (hash == EMPTY_CODE_HASH) {
        return 0;
    }
    const auto& c = contracts_.by_hash(hash);
    if (offset >= c.code_size) {
        return 0;
    }
    const size_t remaining = static_cast<size_t>(c.code_size) - offset;
    const size_t n         = remaining < buffer_size ? remaining : buffer_size;
    std::memcpy(buffer, c.code + offset, n);
    return n;
}

bool ZiskStateDB::selfdestruct(const evmc::address& addr,
                               const evmc::address& beneficiary) noexcept {
    // EIP-6780 same-tx-creation tracking is out of scope. For pre-
    // existing contracts (the common case) selfdestruct now only moves
    // the balance and does NOT destroy the contract — so we always
    // return false (not destroyed) and only do the balance transfer.
    if (addr == beneficiary) {
        // Self-transfer is a no-op on balance (would zero it otherwise).
        return false;
    }

    // Log both balances BEFORE mutating so a revert restores them in
    // the reverse order they were written.
    const size_t src_idx = accounts_.index_of(addr);
    const size_t dst_idx = accounts_.index_of(beneficiary);
    journal_.log_balance(src_idx, accounts_.balance_at(src_idx));
    journal_.log_balance(dst_idx, accounts_.balance_at(dst_idx));

    const auto src_u = intx::be::load<intx::uint256>(accounts_.balance_at(src_idx));
    const auto dst_u = intx::be::load<intx::uint256>(accounts_.balance_at(dst_idx));
    accounts_.set_balance_at(dst_idx, intx::be::store<evmc::uint256be>(dst_u + src_u));
    accounts_.set_balance_at(src_idx, evmc::uint256be{});
    return false;
}

evmc_tx_context ZiskStateDB::get_tx_context() const noexcept {
    return tx_context_;
}

void ZiskStateDB::set_tx_context(const evmc_tx_context& ctx) noexcept {
    tx_context_ = ctx;
}

ZiskStateDB::Checkpoint ZiskStateDB::checkpoint() noexcept {
    // Snapshot the current tx's logs size alongside the journal cp so
    // a reverted frame drops its emissions too.
    return Checkpoint{
        journal_.checkpoint(),
        tx_receipts_.empty() ? size_t{0} : tx_receipts_.back().logs.size(),
    };
}

void ZiskStateDB::rollback(Checkpoint cp) noexcept {
    journal_.rollback(cp.journal_cp, accounts_, storages_, transient_);
    if (!tx_receipts_.empty()) {
        tx_receipts_.back().logs.resize(cp.log_count);
    }
}

evmc::bytes32 ZiskStateDB::get_block_hash(int64_t block_number) const noexcept {
    const int64_t current = static_cast<int64_t>(consensus_.number());
    const int64_t diff    = current - block_number;
    // EVM BLOCKHASH semantics: zero outside [1, 256] (the opcode's own
    // depth limit; EIP-2935 history extends this via the system
    // contract, not via the opcode).
    if (diff < 1 || diff > 256) {
        return {};
    }
    // Walk the parent_hash chain rather than the pre-computed hashes_
    // array. depth 1 = current block's parent, which ConsensusInfo
    // carries directly. depth d ≥ 2 reuses the parent_hash field on
    // PreviousBlocks[d-2] (since that block's parent IS the depth-d
    // ancestor). Out-of-range = zero, matching the EVM convention.
    if (diff == 1) {
        return consensus_.parent_hash();
    }
    const size_t idx = static_cast<size_t>(diff - 2);
    if (idx >= previous_blocks_.size()) {
        return {};
    }
    return previous_blocks_.at(idx).parent_hash();
}

std::span<const uint8_t> ZiskStateDB::code(const evmc::address& addr) const noexcept {
    const auto hash = const_cast<Accounts&>(accounts_).code_hash(addr, tx_counter_);
    if (hash == EMPTY_CODE_HASH) {
        return {};
    }
    const auto& c = contracts_.by_hash(hash);
    return std::span<const uint8_t>{c.code, static_cast<size_t>(c.code_size)};
}

void ZiskStateDB::transfer_value(const evmc::address& from,
                                 const evmc::address& to,
                                 const evmc::uint256be& value) noexcept {
    const size_t from_idx = accounts_.index_of(from);
    const size_t to_idx   = accounts_.index_of(to);
    journal_.log_balance(from_idx, accounts_.balance_at(from_idx));
    journal_.log_balance(to_idx,   accounts_.balance_at(to_idx));

    const auto from_u = intx::be::load<intx::uint256>(accounts_.balance_at(from_idx));
    const auto to_u   = intx::be::load<intx::uint256>(accounts_.balance_at(to_idx));
    const auto v_u    = intx::be::load<intx::uint256>(value);

    // The EVM gated the call on `from_u >= v_u`; we don't re-check.
    accounts_.set_balance_at(from_idx, intx::be::store<evmc::uint256be>(from_u - v_u));
    accounts_.set_balance_at(to_idx,   intx::be::store<evmc::uint256be>(to_u   + v_u));
}

// ===== Unimplementable until additional infrastructure lands =====

evmc::bytes32 ZiskStateDB::get_transient_storage(const evmc::address& addr,
                                                 const evmc::bytes32& key) const noexcept {
    return transient_.get(addr, key);
}

void ZiskStateDB::set_transient_storage(const evmc::address& addr,
                                        const evmc::bytes32& key,
                                        const evmc::bytes32& value) noexcept {
    // Snapshot the slot's pre-write state and journal it BEFORE the
    // mutation so an enclosing revert can restore it. EIP-1153 only
    // requires per-frame reset (handled at tx/system-call boundaries)
    // + per-revert rollback; no warm/cold or "original" semantics.
    const auto prev = transient_.set(addr, key, value);
    journal_.log_transient(addr, key, prev.was_present, prev.value);
}

evmc::Result ZiskStateDB::call_create(const evmc_message& msg,
                                      Checkpoint cp) noexcept {
    // The EVM hands us the init code either via msg.code (modern evmc
    // convention for nested calls) or via msg.input_data (the legacy
    // convention some flows still use). Use whichever is set.
    const uint8_t* init_code = msg.code != nullptr ? msg.code : msg.input_data;
    const size_t   init_size = msg.code != nullptr ? msg.code_size : msg.input_size;

    // 1. Derive the new contract address. Sender's nonce *before* the
    //    create-time increment is the input to the CREATE hash.
    const size_t sender_idx        = accounts_.index_of(msg.sender);
    const uint64_t sender_nonce_pre = accounts_.nonce_at(sender_idx);
    evmc::address new_addr;
    if (msg.kind == EVMC_CREATE) {
        new_addr = compute_create_address(msg.sender, sender_nonce_pre);
    } else {
        // EVMC_CREATE2 / EVMC_EOFCREATE — same formula, distinguished
        // only by what bytes the EVM hands us as the init code.
        new_addr = compute_create2_address(msg.sender, msg.create2_salt,
                                           init_code, init_size);
    }

    // 2. Bump sender nonce (journaled).
    journal_.log_nonce(sender_idx, sender_nonce_pre);
    accounts_.set_nonce_at(sender_idx, sender_nonce_pre + 1);

    // 3. EIP-684 collision check on the new account. The prover must
    //    have included this address in the witness (otherwise
    //    index_of fatals); it should look empty (nonce == 0 and
    //    code_hash == EMPTY).
    const size_t new_idx = accounts_.index_of(new_addr);
    if (accounts_.nonce_at(new_idx) != 0 ||
        accounts_.code_hash_at(new_idx) != EMPTY_CODE_HASH) {
        rollback(cp);
        return evmc::Result{EVMC_FAILURE, 0, 0, nullptr, 0};
    }

    // 4. Initialize the new account: nonce = 1 (post EIP-161) and the
    //    value transfer.
    journal_.log_nonce(new_idx, accounts_.nonce_at(new_idx));
    accounts_.set_nonce_at(new_idx, 1);

    const auto v_u = intx::be::load<intx::uint256>(msg.value);
    if (v_u != 0) {
        transfer_value(msg.sender, new_addr, msg.value);
    }

    // 5. Execute the init code with the new address as the recipient.
    evmc_message create_msg = msg;
    create_msg.recipient    = new_addr;

    auto result = vm_.execute(*this, EVMC_OSAKA, create_msg,
                              init_code, init_size);
    if (result.status_code != EVMC_SUCCESS) {
        rollback(cp);
        return result;
    }

    // 6. Register the deployed code on the new account. The Contracts
    //    table is consulted lazily by `code()` / `copy_code()` /
    //    `get_code_size()` only if the new contract is read later in
    //    this block; if it isn't, the prover correctly omits the
    //    Contracts entry. No witness-completeness check needed here.
    const auto deployed_hash =
        keccak256_bytes32(result.output_data, result.output_size);
    journal_.log_code_hash(new_idx, accounts_.code_hash_at(new_idx));
    accounts_.set_code_hash_at(new_idx, deployed_hash);

    result.create_address = new_addr;
    return result;
}

evmc::Result ZiskStateDB::call(const evmc_message& msg) noexcept {
    // Snapshot state up front. Any non-success status from the nested
    // frame rolls back every write made under it.
    const auto cp = checkpoint();

    std::span<const uint8_t> code;

    switch (msg.kind) {
        case EVMC_CALL: {
            // CALL transfers `value` from sender to recipient.
            // STATICCALL is just an EVMC_CALL with msg.flags &
            // EVMC_STATIC and value forced to 0 by EIP-214, so the
            // `v_u != 0` guard naturally skips the transfer for it.
            // DELEGATECALL/CALLCODE never transfer (handled below).
            const auto v_u = intx::be::load<intx::uint256>(msg.value);
            if (v_u != 0) {
                transfer_value(msg.sender, msg.recipient, msg.value);
            }
            code = this->code(msg.code_address);
            break;
        }
        case EVMC_CALLCODE:
        case EVMC_DELEGATECALL:
            // No value transfer (DELEGATECALL's `value` is apparent
            // only; CALLCODE keeps the value in the caller's storage).
            code = this->code(msg.code_address);
            break;

        case EVMC_CREATE:
        case EVMC_CREATE2:
        case EVMC_EOFCREATE:
            return call_create(msg, cp);
    }

    auto result = vm_.execute(*this, EVMC_OSAKA, msg,
                              code.data(), code.size());
    if (result.status_code != EVMC_SUCCESS) {
        rollback(cp);
    }
    return result;
}

void ZiskStateDB::emit_log(const evmc::address& addr,
                           const uint8_t* data,
                           size_t data_size,
                           const evmc::bytes32 topics[],
                           size_t topics_count) noexcept {
    // The current tx's receipt was pushed onto tx_receipts_ at the
    // start of the iteration in process_transactions; we just append
    // the log here. Owned copies so the EVM is free to release its
    // buffers after this returns.
    LogEntry entry;
    entry.address = addr;
    entry.topics.assign(topics, topics + topics_count);
    entry.data.assign  (data,   data   + data_size);
    tx_receipts_.back().logs.push_back(std::move(entry));
}

evmc_access_status ZiskStateDB::access_account(const evmc::address& addr) noexcept {
    // EIP-2929 account warm/cold: warm iff the account was already
    // touched in this tx (last_tx_idx == tx_counter_). Either way,
    // touch it now so the next access sees it warm. Same pattern as
    // access_storage.
    const size_t idx      = accounts_.index_of(addr);
    const bool   was_warm = accounts_.is_warm_at(idx, tx_counter_);
    accounts_.mark_touched_at(idx, tx_counter_);
    return was_warm ? EVMC_ACCESS_WARM : EVMC_ACCESS_COLD;
}

evmc_access_status ZiskStateDB::access_storage(const evmc::address& addr,
                                               const evmc::bytes32& key) noexcept {
    // EIP-2929 warm/cold: a slot is warm iff it was already touched in
    // this tx (last_tx_idx == tx_counter_). Either way, touch it now
    // so the next access sees it warm.
    const size_t idx       = storages_.index_of(addr, key);
    const bool   was_warm  = storages_.is_warm_at(idx, tx_counter_);
    storages_.mark_touched_at(idx, tx_counter_);
    return was_warm ? EVMC_ACCESS_WARM : EVMC_ACCESS_COLD;
}

// ============================================================================
// Block-execution driver — single public entry that chains the three
// per-phase helpers.
// ============================================================================

void ZiskStateDB::execute_block(const Transactions& transactions) noexcept {
    pre_execute_block ();
    process_transactions(transactions);
    post_execute_block();

    // Receipts trie root: built from the finalized tx_receipts_, one
    // leaf per tx keyed by RLP(tx_index).
    {
        MerklePatriciaTrie trie;
        for (size_t i = 0; i < tx_receipts_.size(); ++i) {
            trie.insert(rlp::encode_u64(i), encode_receipt(tx_receipts_[i]));
        }
        receipts_root_ = trie.root_hash();
    }

    // Withdrawals trie root (EIP-4895): one leaf per withdrawal, keyed
    // by RLP(index_in_block), value = rlp_list(index, validator_index,
    // address, amount_gwei). Empty list → empty-trie root.
    {
        MerklePatriciaTrie trie;
        for (size_t i = 0; i < consensus_.withdrawals_count(); ++i) {
            const auto& w           = consensus_.withdrawal(i);
            const auto  index_rlp           = rlp::encode_u64(w.index());
            const auto  validator_index_rlp = rlp::encode_u64(w.validator_index());
            const auto  address_rlp         = rlp::encode(rlp::BytesView{w.address().bytes,
                                                                          sizeof(w.address().bytes)});
            const auto  amount_rlp          = rlp::encode_u64(w.amount_gwei());
            auto record = rlp::encode_list({index_rlp,
                                            validator_index_rlp,
                                            address_rlp,
                                            amount_rlp});
            trie.insert(rlp::encode_u64(i), std::move(record));
        }
        withdrawals_root_ = trie.root_hash();
    }

    // EIP-7685 requests_hash: sha256(sha256(req[0]) || sha256(req[1])
    // || ...) over the type-prefixed request blobs in requests_.
    // Empty list collapses to sha256("") per the EIP.
    {
        std::vector<uint8_t> concatenated;
        concatenated.reserve(requests_.size() * 32);
        for (const auto& req : requests_) {
            const auto inner = sha256_bytes32(req.data(), req.size());
            concatenated.insert(concatenated.end(),
                                std::begin(inner.bytes),
                                std::end(inner.bytes));
        }
        requests_hash_ = sha256_bytes32(concatenated.data(), concatenated.size());
    }
}

evmc::Result ZiskStateDB::system_call(const evmc::address&     target,
                                      std::span<const uint8_t> calldata) noexcept {
    // Treat every system call as its own EVM frame for the purposes
    // of EIP-2929 warm/cold + EIP-2200 per-tx-original tracking. The
    // bump matters even though system calls don't pay gas: without
    // it, the very first access inside the frame would run with
    // tx_counter_ matching the never-touched sentinel (0), which
    // would make is_warm_at falsely report `true` and mark_touched_at
    // skip its snapshot. Transient storage (EIP-1153) is also reset
    // per-frame.
    ++tx_counter_;
    transient_.reset();

    evmc_message msg{};
    msg.kind         = EVMC_CALL;
    msg.sender       = kSystemAddress;
    msg.recipient    = target;
    msg.code_address = target;
    msg.input_data   = calldata.data();
    msg.input_size   = calldata.size();
    msg.gas          = kSystemCallGas;
    msg.value        = evmc::uint256be{};       // 0
    msg.depth        = 0;

    // Standard checkpoint+rollback discipline so a reverted system
    // frame doesn't leave half-written state behind. No gas
    // accounting (system calls have no sender to debit / coinbase to
    // pay); the caller may consume the result's output_data (e.g.
    // for EIP-7002 / EIP-7251 request dequeue).
    const auto cp = checkpoint();
    const auto entry_code = code(target);
    auto result = vm_.execute(*this, EVMC_OSAKA, msg,
                              entry_code.data(), entry_code.size());
    if (result.status_code != EVMC_SUCCESS) {
        rollback(cp);
    }
    return result;
}

void ZiskStateDB::pre_execute_block() noexcept {
    // Block-level tx_context: persists across every tx in this block.
    // process_transactions later overwrites the per-tx fields
    // (tx_origin, tx_gas_price, …) without touching these.
    evmc_tx_context ctx{};
    ctx.block_coinbase    = consensus_.beneficiary();
    ctx.block_number      = static_cast<int64_t>(consensus_.number());
    ctx.block_timestamp   = static_cast<int64_t>(consensus_.timestamp());
    ctx.block_gas_limit   = static_cast<int64_t>(consensus_.gas_limit());
    ctx.block_prev_randao = consensus_.prev_randao();
    ctx.chain_id          = intx::be::store<evmc::uint256be>(
                                intx::uint256{kChainId});
    ctx.block_base_fee    = consensus_.base_fee_per_gas();
    // EIP-4844: blob_base_fee = fake_exponential(1, excess_blob_gas,
    //                                            3338477).
    ctx.blob_base_fee     = intx::be::store<evmc::uint256be>(
        fake_exponential(kMinBaseFeePerBlobGas,
                         consensus_.excess_blob_gas(),
                         kBlobBaseFeeUpdateFraction));
    set_tx_context(ctx);

    // EIP-4788: write the parent's beacon block root into the beacon
    // roots predeploy. The contract's storage maps timestamp →
    // parent_beacon_block_root in a 8191-slot ring buffer so the
    // CL/EL can prove past beacon roots.
    {
        const auto& root = consensus_.parent_beacon_block_root();
        (void)system_call(kBeaconRootsAddress,
                          std::span<const uint8_t>{root.bytes, 32});
    }

    // EIP-2935: write the parent's block hash into the history
    // storage contract. The contract stores hashes indexed by
    // (block_number) so BLOCKHASH can reach further back than the
    // opcode's 256-block window via the predeploy.
    {
        const auto& parent = consensus_.parent_hash();
        (void)system_call(kHistoryStorageAddress,
                          std::span<const uint8_t>{parent.bytes, 32});
    }
}

void ZiskStateDB::process_transactions(const Transactions& transactions) noexcept {
    using TxType = Transactions::Type;

    for (size_t i = 0; i < transactions.size(); ++i) {
        // Bump the tx counter BEFORE any Storages access — so the
        // very first SLOAD/SSTORE/access in this tx sees a fresh
        // tx_idx and trips Storages::mark_touched_at's snapshot
        // path. Starts the first tx at counter 1 (> 0 sentinel).
        // Transient storage (EIP-1153) is also reset per-tx.
        ++tx_counter_;
        transient_.reset();

        const auto& tx = transactions.at(i);

        // Push the receipt for this tx up front. emit_log appends to
        // tx_receipts_.back().logs during execution; we finalize
        // status / bloom / cumGas at the end of the iteration.
        {
            auto& rcpt   = tx_receipts_.emplace_back();
            rcpt.tx_type = tx.type();
        }

        // Backing storage for the blob-hashes and initcodes arrays we
        // point ctx at. Both must outlive vm_.execute below since the
        // ctx fields are raw pointers into these vectors.
        std::vector<evmc::bytes32>    blob_hashes;
        std::vector<evmc_tx_initcode> initcodes_vec;

        // Per-tx tx_context update. Block-level fields were set once
        // by pre_execute_block and persist across iterations; we still
        // reset any per-tx fields that might have lingered from a
        // previous iteration (blob_hashes / initcodes pointers).
        {
            auto ctx      = tx_context_;
            ctx.tx_origin = tx.sender();
            // Effective gas-price approximation. Proper EIP-1559 form
            // is min(max_fee_per_gas, base_fee + max_priority_fee);
            // using max_fee_per_gas as an upper bound is a TODO for
            // accurate gas accounting.
            ctx.tx_gas_price = (tx.type() == TxType::Legacy ||
                                tx.type() == TxType::AccessList)
                                   ? tx.gas_price()
                                   : tx.max_fee_per_gas();

            // EIP-4844 blob_hashes — only Type-3 carries them; other
            // types leave the pair zeroed.
            ctx.blob_hashes       = nullptr;
            ctx.blob_hashes_count = 0;
            if (tx.type() == TxType::Blob) {
                const auto raw   = tx.blob_versioned_hashes_rlp();
                const auto outer = rlp::decode_item(raw);
                if (outer.kind != rlp::ItemKind::List) {
                    fatal("blob_versioned_hashes is not an RLP list");
                }
                rlp::ListIter it{outer.payload};
                while (it.has_next()) {
                    const auto item = it.next();
                    if (item.kind != rlp::ItemKind::String ||
                        item.payload.size() != 32) {
                        fatal("blob_versioned_hashes: expected 32-byte string");
                    }
                    evmc::bytes32 h;
                    std::memcpy(h.bytes, item.payload.data(), 32);
                    blob_hashes.push_back(h);
                }
                ctx.blob_hashes       = blob_hashes.data();
                ctx.blob_hashes_count = blob_hashes.size();
                // Accumulate the block-level blob_gas_used field
                // (EIP-4844). The per-tx fee debit happens further
                // below (sender pays blob_gas × blob_base_fee); this
                // is just the running header total.
                blob_gas_used_ += blob_hashes.size() * kGasPerBlob;
            }

            // EIP-7873 initcodes — Type 5 (Osaka) only. Each entry's
            // `code` points zero-copy into the envelope; `hash` is
            // keccak256 of those bytes (the TXCREATE lookup key).
            ctx.initcodes       = nullptr;
            ctx.initcodes_count = 0;
            if (tx.type() == TxType::Osaka) {
                const auto raw   = tx.initcodes_rlp();
                const auto outer = rlp::decode_item(raw);
                if (outer.kind != rlp::ItemKind::List) {
                    fatal("Osaka tx: initcodes is not an RLP list");
                }
                rlp::ListIter it{outer.payload};
                while (it.has_next()) {
                    const auto item = it.next();
                    if (item.kind != rlp::ItemKind::String) {
                        fatal("Osaka tx: initcodes entry is not an RLP string");
                    }
                    evmc_tx_initcode entry{};
                    entry.code      = item.payload.data();
                    entry.code_size = item.payload.size();
                    entry.hash      = keccak256_bytes32(entry.code, entry.code_size);
                    initcodes_vec.push_back(entry);
                }
                ctx.initcodes       = initcodes_vec.data();
                ctx.initcodes_count = initcodes_vec.size();
            }

            set_tx_context(ctx);
        }

        // ===== Pre-EVM accounting (NOT journaled — survives revert) =====
        // EIP-161 / YP §6: sender nonce += 1, then debit upfront gas
        // (gas_limit × eff_gas_price + blob_gas × blob_base_fee). The
        // blob portion is burned. These changes are kept even if the
        // EVM frame reverts, matching mainnet semantics.
        const size_t sender_idx     = accounts_.index_of(tx.sender());
        const int64_t intrinsic_gas = compute_intrinsic_gas(tx);
        if (static_cast<int64_t>(tx.gas_limit()) < intrinsic_gas) {
            fatal("tx gas_limit below intrinsic gas");
        }

        accounts_.set_nonce_at(sender_idx, accounts_.nonce_at(sender_idx) + 1);

        const auto eff_gas_price_u =
            intx::be::load<intx::uint256>(tx_context_.tx_gas_price);
        auto upfront_u = intx::uint256{tx.gas_limit()} * eff_gas_price_u;
        // EIP-4844 blob gas charge for Type-3 txs. Each blob costs
        // kGasPerBlob blob-gas; the per-gas price is blob_base_fee
        // (already computed in pre_execute_block and stored in
        // tx_context_). Burned, not paid to coinbase.
        if (tx.type() == TxType::Blob) {
            const auto blob_gas_u =
                intx::uint256{blob_hashes.size() * kGasPerBlob};
            const auto blob_fee_u =
                intx::be::load<intx::uint256>(tx_context_.blob_base_fee);
            upfront_u += blob_gas_u * blob_fee_u;
        }
        {
            const auto bal_u =
                intx::be::load<intx::uint256>(accounts_.balance_at(sender_idx));
            // Tx validity: sender must be able to cover the entire
            // upfront cost (execution gas + blob fee + value would
            // also count if not transferred separately by the EVM
            // frame — here just upfront gas + blob, since value
            // transfer is journaled inside the checkpoint below).
            if (bal_u < upfront_u) {
                fatal("tx sender balance below upfront cost");
            }
            accounts_.set_balance_at(sender_idx,
                intx::be::store<evmc::uint256be>(bal_u - upfront_u));
        }

        // ===== EIP-7702 authorization list (Type-4 only) =====
        //
        // Per-tx refund accumulator: PER_EMPTY_ACCOUNT_COST −
        // PER_AUTH_BASE_COST = 12500 gas per auth whose signer's
        // account already existed (non-empty) before this tx. Folded
        // into the post-EVM refund total below.
        int64_t auth_refund = 0;
        //
        // Per the EIP, authorizations are applied at the START of the
        // tx (before EVM execution), so the EVM sees the resulting
        // delegations. They also SURVIVE EVM revert, just like the
        // tx-level nonce bump — so we apply them here (before the
        // checkpoint) using raw setters (no journaling). Each auth
        // that fails its validity checks is silently skipped per the
        // EIP. The 25k-per-auth intrinsic-gas cost is already
        // included via compute_intrinsic_gas above; the 12500 refund
        // per pre-existing delegation accumulates in `auth_refund`
        // below and folds into the post-EVM refund total.
        if (tx.type() == TxType::SetCode) {
            const auto auth_outer = rlp::decode_item(tx.authorization_list_rlp());
            if (auth_outer.kind != rlp::ItemKind::List) {
                fatal("EIP-7702: authorization_list is not an RLP list");
            }
            rlp::ListIter auth_it{auth_outer.payload};
            size_t auth_idx = 0;
            while (auth_it.has_next()) {
                const auto auth_item = auth_it.next();
                if (auth_item.kind != rlp::ItemKind::List) {
                    fatal("EIP-7702: authorization entry not an RLP list");
                }
                rlp::ListIter fit{auth_item.payload};
                if (!fit.has_next()) fatal("EIP-7702: auth missing chain_id");
                const uint64_t a_chain_id = rlp::as_u64(fit.next());
                if (!fit.has_next()) fatal("EIP-7702: auth missing address");
                const auto a_addr_item = fit.next();
                if (a_addr_item.kind != rlp::ItemKind::String ||
                    a_addr_item.payload.size() != 20) {
                    fatal("EIP-7702: auth address not a 20-byte string");
                }
                evmc::address delegate;
                std::memcpy(delegate.bytes, a_addr_item.payload.data(), 20);
                if (!fit.has_next()) fatal("EIP-7702: auth missing nonce");
                const uint64_t a_nonce = rlp::as_u64(fit.next());
                if (!fit.has_next()) fatal("EIP-7702: auth missing y_parity");
                (void)rlp::as_u64(fit.next());  // y_parity — not used here
                if (!fit.has_next()) fatal("EIP-7702: auth missing r");
                const auto a_r = rlp::as_u256(fit.next());
                if (!fit.has_next()) fatal("EIP-7702: auth missing s");
                const auto a_s = rlp::as_u256(fit.next());

                // chain_id must be 0 (universal) or match the
                // current chain id; otherwise skip.
                if (a_chain_id != 0 &&
                    a_chain_id != kChainId) {
                    ++auth_idx;
                    continue;
                }

                // Auth signing hash: keccak256(0x05 || rlp([chain_id,
                // address, nonce])).
                const auto cid_enc   = rlp::encode_u64(a_chain_id);
                const auto addr_enc  = rlp::encode(
                    rlp::BytesView{delegate.bytes, 20});
                const auto nonce_enc = rlp::encode_u64(a_nonce);
                const auto list_enc  = rlp::encode_list({
                    rlp::BytesView{cid_enc.data(),   cid_enc.size()},
                    rlp::BytesView{addr_enc.data(),  addr_enc.size()},
                    rlp::BytesView{nonce_enc.data(), nonce_enc.size()},
                });
                std::vector<uint8_t> preimage;
                preimage.reserve(1 + list_enc.size());
                preimage.push_back(0x05);
                preimage.insert(preimage.end(),
                                list_enc.begin(), list_enc.end());
                const auto a_hash = keccak256_bytes32(
                    preimage.data(), preimage.size());

                // Verify against prover-supplied pubkey, recover signer.
                const auto pk_span = tx.auth_pubkey(auth_idx);
                const evmc::address signer =
                    verify_signature_and_get_signer(pk_span.data(),
                                                    a_hash, a_r, a_s);

                // Signer must be in the witness with the matching
                // nonce. Skip on mismatch.
                const size_t signer_idx = accounts_.index_of(signer);
                if (accounts_.nonce_at(signer_idx) != a_nonce) {
                    ++auth_idx;
                    continue;
                }

                // EIP-7702 refund: PER_EMPTY_ACCOUNT_COST minus
                // PER_AUTH_BASE_COST (25000 − 12500 = 12500) per auth
                // whose signer's account already had state. Read
                // BEFORE we mutate the signer's nonce/code below.
                const bool signer_was_non_empty =
                    accounts_.nonce_at(signer_idx) != 0 ||
                    accounts_.code_hash_at(signer_idx) != EMPTY_CODE_HASH;
                if (signer_was_non_empty) {
                    auth_refund += 12500;
                }

                // Bump signer's nonce + set delegation code_hash =
                // keccak(0xef0100 || delegate). Raw setters — these
                // changes survive any EVM revert below.
                accounts_.set_nonce_at(signer_idx, a_nonce + 1);

                uint8_t delegation[23];
                delegation[0] = 0xef;
                delegation[1] = 0x01;
                delegation[2] = 0x00;
                std::memcpy(delegation + 3, delegate.bytes, 20);
                const auto delegation_hash = keccak256_bytes32(
                    delegation, sizeof(delegation));
                accounts_.set_code_hash_at(signer_idx, delegation_hash);

                ++auth_idx;
            }
        }

        // ===== EVM execution =====
        evmc_message msg{};
        msg.sender = tx.sender();
        msg.value  = tx.value();
        msg.gas    = static_cast<int64_t>(tx.gas_limit()) - intrinsic_gas;
        msg.depth  = 0;

        // Checkpoint AFTER the upfront accounting + EIP-7702 auths so
        // none of those are rolled back on EVM revert. State changes
        // made inside the checkpoint (value transfer, EVM writes) are
        // undone if any phase fails.
        const auto cp = checkpoint();

        std::span<const uint8_t> entry_code;
        evmc::Result result;

        if (tx.to() == nullptr) {
            // ----- Top-level CREATE -----
            //
            // Derive new address using sender's pre-bump nonce (= the
            // current value minus 1, since we just bumped at tx
            // level). Set up the new account (nonce = 1, balance gets
            // the value transfer), then run init code; on success,
            // register the deployed code on the new account.
            const uint64_t sender_nonce_pre =
                accounts_.nonce_at(sender_idx) - 1;
            const evmc::address new_addr =
                compute_create_address(tx.sender(), sender_nonce_pre);

            msg.kind      = EVMC_CREATE;
            msg.recipient = new_addr;
            entry_code    = tx.data();

            const size_t new_idx = accounts_.index_of(new_addr);
            // EIP-684 collision: if the target already has a nonce or
            // code, the CREATE fails with all gas consumed.
            if (accounts_.nonce_at(new_idx) != 0 ||
                accounts_.code_hash_at(new_idx) != EMPTY_CODE_HASH) {
                result = evmc::Result{EVMC_FAILURE, 0, 0, nullptr, 0};
            } else {
                // Initialize the new account (nonce = 1) and transfer
                // value. Both go through the journal so a revert
                // unwinds them.
                journal_.log_nonce(new_idx, accounts_.nonce_at(new_idx));
                accounts_.set_nonce_at(new_idx, 1);
                if (intx::be::load<intx::uint256>(msg.value) != 0) {
                    transfer_value(msg.sender, new_addr, msg.value);
                }

                result = vm_.execute(*this, EVMC_OSAKA, msg,
                                     entry_code.data(), entry_code.size());

                if (result.status_code == EVMC_SUCCESS) {
                    const auto deployed_hash = keccak256_bytes32(
                        result.output_data, result.output_size);
                    journal_.log_code_hash(new_idx,
                                           accounts_.code_hash_at(new_idx));
                    accounts_.set_code_hash_at(new_idx, deployed_hash);
                    result.create_address = new_addr;
                }
            }
        } else {
            // ----- Top-level CALL -----
            msg.kind         = EVMC_CALL;
            msg.recipient    = *tx.to();
            msg.code_address = *tx.to();
            msg.input_data   = tx.data().data();
            msg.input_size   = tx.data().size();
            entry_code       = this->code(msg.recipient);

            if (intx::be::load<intx::uint256>(msg.value) != 0) {
                transfer_value(msg.sender, msg.recipient, msg.value);
            }

            result = vm_.execute(*this, EVMC_OSAKA, msg,
                                 entry_code.data(), entry_code.size());
        }

        if (result.status_code != EVMC_SUCCESS) {
            rollback(cp);
        }

        // ===== Post-EVM accounting (NOT journaled — final settlement) =====
        // result.gas_left is what remains of `msg.gas` (already net of
        // intrinsic). Total tx gas used is gas_limit − gas_left.
        // EIP-3529 (London+): refund is capped at gas_used / 5.
        const int64_t gas_left      = result.gas_left;
        const int64_t gas_used_pre  =
            static_cast<int64_t>(tx.gas_limit()) - gas_left;
        const int64_t max_refund    = gas_used_pre / 5;
        // EVM-level refund (storage clears, etc.) plus EIP-7702
        // auth-list refund (12500 per pre-existing signer). Both are
        // subject to the same EIP-3529 cap.
        const int64_t refund_pre_cap = result.gas_refund + auth_refund;
        const int64_t refund         =
            (refund_pre_cap < max_refund) ? refund_pre_cap : max_refund;
        const int64_t gas_remaining = gas_left + refund;
        const int64_t gas_used      =
            static_cast<int64_t>(tx.gas_limit()) - gas_remaining;

        // Refund sender: gas_remaining × effective_gas_price.
        {
            const auto credit_u =
                intx::uint256{static_cast<uint64_t>(gas_remaining)} * eff_gas_price_u;
            const auto bal_u =
                intx::be::load<intx::uint256>(accounts_.balance_at(sender_idx));
            accounts_.set_balance_at(sender_idx,
                intx::be::store<evmc::uint256be>(bal_u + credit_u));
        }

        // Pay coinbase the priority-fee portion only (EIP-1559: the
        // base-fee portion is burned). priority_fee = max(0,
        // effective_gas_price − base_fee). The blob-gas portion is
        // burned and never paid to coinbase.
        {
            const auto base_fee_u =
                intx::be::load<intx::uint256>(consensus_.base_fee_per_gas());
            const auto priority_u = (eff_gas_price_u > base_fee_u)
                                        ? (eff_gas_price_u - base_fee_u)
                                        : intx::uint256{0};
            const auto fee_u =
                intx::uint256{static_cast<uint64_t>(gas_used)} * priority_u;
            const size_t coinbase_idx =
                accounts_.index_of(consensus_.beneficiary());
            const auto bal_u =
                intx::be::load<intx::uint256>(accounts_.balance_at(coinbase_idx));
            accounts_.set_balance_at(coinbase_idx,
                intx::be::store<evmc::uint256be>(bal_u + fee_u));
        }

        // ===== Receipt finalization =====
        // The in-progress receipt was pushed at the start of the
        // iteration and emit_log filled its `logs` (with revert
        // truncation via rollback). Compute the per-tx bloom now from
        // whatever logs survived, then OR into the block bloom, set
        // status + cumGas.
        {
            auto& rcpt = tx_receipts_.back();
            for (const auto& log : rcpt.logs) {
                bloom_add(rcpt.logs_bloom,
                          log.address.bytes, sizeof(log.address.bytes));
                for (const auto& t : log.topics) {
                    bloom_add(rcpt.logs_bloom, t.bytes, sizeof(t.bytes));
                }
            }
            for (size_t j = 0; j < 256; ++j) {
                block_bloom_filter_[j] |= rcpt.logs_bloom[j];
            }
            cumulative_gas_used_     += static_cast<uint64_t>(gas_used);
            rcpt.cumulative_gas_used  = cumulative_gas_used_;
            rcpt.status               = (result.status_code == EVMC_SUCCESS);
        }
    }
}

void ZiskStateDB::post_execute_block() noexcept {
    // ===== EIP-4895: credit each withdrawal to its recipient =====
    // Withdrawal amounts are in gwei; balances are in wei.
    const auto gwei_to_wei = intx::uint256{1'000'000'000};
    for (const auto& w : consensus_.withdrawals()) {
        const size_t idx = accounts_.index_of(w.address());
        const auto   bal_u =
            intx::be::load<intx::uint256>(accounts_.balance_at(idx));
        const auto credit_u =
            intx::uint256{w.amount_gwei()} * gwei_to_wei;
        accounts_.set_balance_at(idx,
            intx::be::store<evmc::uint256be>(bal_u + credit_u));
    }

    // ===== EIP-6110 deposit requests =====
    // Scan tx_receipts_ for `DepositEvent` logs emitted by the beacon-
    // deposit contract. Each event carries five `bytes` fields
    // (pubkey 48, withdrawal_credentials 32, amount 8, signature 96,
    // index 8); per EIP-6110 the deposit request body is those five
    // fields concatenated in spec order = 192 bytes per deposit. All
    // deposits for the block aggregate into one type-0x00 entry.
    //
    // Pushed FIRST so requests_ stays in EIP-7685 type-byte order
    // (0x00 → 0x01 → 0x02). Reverted logs were already dropped from
    // tx_receipts_ via the journal/log-checkpoint mechanism.
    {
        // keccak256("DepositEvent(bytes,bytes,bytes,bytes,bytes)").
        // Computed once on first entry; cheap, and avoids a wrong
        // hardcoded value going undetected.
        static const evmc::bytes32 deposit_event_topic = [] {
            const char sig[] = "DepositEvent(bytes,bytes,bytes,bytes,bytes)";
            return keccak256_bytes32(reinterpret_cast<const uint8_t*>(sig),
                                     sizeof(sig) - 1);
        }();

        std::vector<uint8_t> deposits_buf;
        for (const auto& receipt : tx_receipts_) {
            for (const auto& log : receipt.logs) {
                if (log.address != kDepositContractAddress) continue;
                if (log.topics.empty())                       continue;
                if (log.topics[0] != deposit_event_topic)     continue;

                const uint8_t* d   = log.data.data();
                const size_t   dsz = log.data.size();
                const auto pubkey_f = abi_read_bytes_field(d, dsz, 0);
                const auto wc_f     = abi_read_bytes_field(d, dsz, 1);
                const auto amount_f = abi_read_bytes_field(d, dsz, 2);
                const auto sig_f    = abi_read_bytes_field(d, dsz, 3);
                const auto index_f  = abi_read_bytes_field(d, dsz, 4);
                if (pubkey_f.length != 48 || wc_f.length != 32 ||
                    amount_f.length != 8  || sig_f.length != 96 ||
                    index_f.length  != 8) {
                    fatal("EIP-6110: DepositEvent field has wrong size");
                }
                deposits_buf.insert(deposits_buf.end(),
                    pubkey_f.data, pubkey_f.data + 48);
                deposits_buf.insert(deposits_buf.end(),
                    wc_f.data,     wc_f.data     + 32);
                deposits_buf.insert(deposits_buf.end(),
                    amount_f.data, amount_f.data + 8);
                deposits_buf.insert(deposits_buf.end(),
                    sig_f.data,    sig_f.data    + 96);
                deposits_buf.insert(deposits_buf.end(),
                    index_f.data,  index_f.data  + 8);
            }
        }
        if (!deposits_buf.empty()) {
            std::vector<uint8_t> req;
            req.reserve(1 + deposits_buf.size());
            req.push_back(kRequestTypeDeposit);
            req.insert(req.end(),
                       deposits_buf.begin(), deposits_buf.end());
            requests_.push_back(std::move(req));
        }
    }

    // ===== EIP-7002 withdrawal requests =====
    // Calling the predeploy with empty calldata dequeues all pending
    // requests; the EVM returns N × 76 bytes (a concatenation of
    // 76-byte records). Per EIP-7685, we prepend the type byte 0x01
    // to the raw queue dump and push it as one request-list entry.
    {
        auto result = system_call(kWithdrawalRequestsAddress, {});
        if (result.status_code == EVMC_SUCCESS && result.output_size > 0) {
            if (result.output_size % 76 != 0) {
                fatal("EIP-7002: queue dump not a multiple of 76 bytes");
            }
            std::vector<uint8_t> req;
            req.reserve(1 + result.output_size);
            req.push_back(kRequestTypeWithdrawal);
            req.insert(req.end(), result.output_data,
                                  result.output_data + result.output_size);
            requests_.push_back(std::move(req));
        }
    }

    // ===== EIP-7251 consolidation requests =====
    // Same shape as EIP-7002, but each record is 116 bytes (20 +
    // 48 + 48) and the request type byte is 0x02.
    {
        auto result = system_call(kConsolidationRequestsAddress, {});
        if (result.status_code == EVMC_SUCCESS && result.output_size > 0) {
            if (result.output_size % 116 != 0) {
                fatal("EIP-7251: queue dump not a multiple of 116 bytes");
            }
            std::vector<uint8_t> req;
            req.reserve(1 + result.output_size);
            req.push_back(kRequestTypeConsolidation);
            req.insert(req.end(), result.output_data,
                                  result.output_data + result.output_size);
            requests_.push_back(std::move(req));
        }
    }

}

} // namespace zeg

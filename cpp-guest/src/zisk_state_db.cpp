#include "zeg/zisk_state_db.hpp"

#include <cstring>
#include <vector>

#include <evmone/evmone.h>  // evmc_create_evmone for the owned VM instance
#include <intx/intx.hpp>    // 256-bit add for selfdestruct balance transfer

#include "zeg/fatal.hpp"
#include "zeg/keccak.hpp"
#include "zeg/rlp.hpp"
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
//   base + sum over calldata: 4 (zero byte) or 16 (non-zero, EIP-2028)
//   + EIP-3860 initcode word cost for creates
// TODO: EIP-2930 access list (2400/addr + 1900/key) and EIP-7702
// authorization list (25k/auth) extras are not folded in yet.
int64_t compute_intrinsic_gas(const Transactions::View& tx) {
    int64_t gas = (tx.to() == nullptr) ? 53000 : 21000;
    for (uint8_t b : tx.data()) {
        gas += (b == 0) ? 4 : 16;
    }
    if (tx.to() == nullptr) {
        gas += static_cast<int64_t>((tx.data().size() + 31) / 32) * 2;
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
    return storages_.value(addr, key);
}

evmc_storage_status ZiskStateDB::set_storage(const evmc::address& addr,
                                             const evmc::bytes32& key,
                                             const evmc::bytes32& value) noexcept {
    // Log the pre-write value first so a later revert can restore it,
    // then perform the mutation. Proper EIP-2200/3529 status tracking
    // (gas-refund-accurate) is a follow-up; ASSIGNED is the catch-all
    // per evmc — gas refunds will be slightly off but the state
    // transition itself is correct.
    const size_t idx = storages_.index_of(addr, key);
    journal_.log_storage(idx, storages_.value_at(idx));
    storages_.set_value_at(idx, value);
    return EVMC_STORAGE_ASSIGNED;
}

evmc::uint256be ZiskStateDB::get_balance(const evmc::address& addr) const noexcept {
    return accounts_.balance(addr);
}

evmc::bytes32 ZiskStateDB::get_code_hash(const evmc::address& addr) const noexcept {
    return accounts_.code_hash(addr);
}

size_t ZiskStateDB::get_code_size(const evmc::address& addr) const noexcept {
    const auto hash = accounts_.code_hash(addr);
    if (hash == EMPTY_CODE_HASH) {
        return 0;
    }
    return static_cast<size_t>(contracts_.by_hash(hash).code_size);
}

size_t ZiskStateDB::copy_code(const evmc::address& addr,
                              size_t offset,
                              uint8_t* buffer,
                              size_t buffer_size) const noexcept {
    const auto hash = accounts_.code_hash(addr);
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

Journal::Checkpoint ZiskStateDB::checkpoint() noexcept {
    return journal_.checkpoint();
}

void ZiskStateDB::rollback(Journal::Checkpoint cp) noexcept {
    journal_.rollback(cp, accounts_, storages_);
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
    const auto hash = accounts_.code_hash(addr);
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

evmc::bytes32 ZiskStateDB::get_transient_storage(const evmc::address&,
                                                 const evmc::bytes32&) const noexcept {
    fatal("ZiskStateDB::get_transient_storage: not yet implemented");
    return {};
}

void ZiskStateDB::set_transient_storage(const evmc::address&,
                                        const evmc::bytes32&,
                                        const evmc::bytes32&) noexcept {
    fatal("ZiskStateDB::set_transient_storage: not yet implemented");
}

evmc::Result ZiskStateDB::call_create(const evmc_message& msg,
                                      Journal::Checkpoint cp) noexcept {
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

void ZiskStateDB::emit_log(const evmc::address&,
                           const uint8_t*,
                           size_t,
                           const evmc::bytes32[],
                           size_t) noexcept {
    fatal("ZiskStateDB::emit_log: log collector not yet implemented");
}

evmc_access_status ZiskStateDB::access_account(const evmc::address&) noexcept {
    fatal("ZiskStateDB::access_account: EIP-2929 access list not yet implemented");
    return EVMC_ACCESS_COLD;
}

evmc_access_status ZiskStateDB::access_storage(const evmc::address&,
                                               const evmc::bytes32&) noexcept {
    fatal("ZiskStateDB::access_storage: EIP-2929 access list not yet implemented");
    return EVMC_ACCESS_COLD;
}

// ============================================================================
// Block-execution driver — single public entry that chains the three
// per-phase helpers.
// ============================================================================

void ZiskStateDB::execute_block(const Transactions& transactions) noexcept {
    pre_execute_block ();
    process_transactions(transactions);
    post_execute_block();
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
                                intx::uint256{consensus_.chain_id()});
    ctx.block_base_fee    = consensus_.base_fee_per_gas();
    // EIP-4844: blob_base_fee = fake_exponential(1, excess_blob_gas,
    //                                            3338477).
    ctx.blob_base_fee     = intx::be::store<evmc::uint256be>(
        fake_exponential(kMinBaseFeePerBlobGas,
                         consensus_.excess_blob_gas(),
                         kBlobBaseFeeUpdateFraction));
    set_tx_context(ctx);

    // TODO: parse the pre-block descriptor from the stream and use
    // evmone (via `*this` as the Host) to run the EIP-4788 and
    // EIP-2935 system calls.
}

void ZiskStateDB::process_transactions(const Transactions& transactions) noexcept {
    using TxType = Transactions::Type;

    for (size_t i = 0; i < transactions.size(); ++i) {
        const auto& tx = transactions.at(i);

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
            // Sender-balance check is the EVM's responsibility upstream
            // (tx validity). We don't re-check; underflow here would
            // surface as a fatal in any later balance-reading opcode.
            accounts_.set_balance_at(sender_idx,
                intx::be::store<evmc::uint256be>(bal_u - upfront_u));
        }

        // ===== EIP-7702 authorization list (Type-4 only) =====
        //
        // Per the EIP, authorizations are applied at the START of the
        // tx (before EVM execution), so the EVM sees the resulting
        // delegations. They also SURVIVE EVM revert, just like the
        // tx-level nonce bump — so we apply them here (before the
        // checkpoint) using raw setters (no journaling). Each auth
        // that fails its validity checks is silently skipped per the
        // EIP. (TODO: fold the 25k-per-auth intrinsic-gas cost into
        // compute_intrinsic_gas.)
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
                    a_chain_id != consensus_.chain_id()) {
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
        const int64_t refund        =
            (result.gas_refund < max_refund) ? result.gas_refund : max_refund;
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
    }
}

void ZiskStateDB::post_execute_block() noexcept {
    // TODO: apply withdrawal balance credits, then EIP-7002 / EIP-7251.
}

} // namespace zeg

// ZiskStateDB — evmc::Host implementation for the ZisK Ethereum guest.
//
// Owns nothing — borrows the five input-stream collections by
// reference from their lifetime-owners (typically constructed at
// main() scope and outliving this object). `Accounts` / `Storages`
// are mutable refs because EVM host setters mutate them;
// `ConsensusInfo` / `Contracts` / `PreviousBlocks` are read-only.
//
// Most Host overrides are direct pass-throughs to the corresponding
// collection's accessors. The execution-driving ones (`call`,
// `emit_log`, `access_*`) plus the block-execution pipeline
// (`execute_block` and its private helpers) do real work and live
// near the bottom of the cpp.
//
// Pure / reusable helpers live in their own modules and are pulled in
// here only where needed:
//
//   `zeg/bloom`            — Yellow Paper §4.4.2 logs-bloom add / OR
//   `zeg/create_address`   — CREATE / CREATE2 / EOFCREATE derivation
//   `zeg/eip6110_deposit`  — DepositEvent log scan + body packing
//   `zeg/fake_exponential` — EIP-4844 blob-base-fee curve
//   `zeg/intrinsic_gas`    — Yellow Paper §6.2 intrinsic gas
//   `zeg/receipt`          — `LogEntry`, `TxReceipt`, canonical RLP
//   `zeg/system_addresses` — Pectra predeploy addresses + EIP-7685 tags
//   `zeg/zisk_crypto`      — secp256k1 verify + signer recovery

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

#include "zeg/accounts.hpp"
#include "zeg/consensus_info.hpp"
#include "zeg/contracts.hpp"
#include "zeg/journal.hpp"
#include "zeg/previous_blocks.hpp"
#include "zeg/receipt.hpp"           // LogEntry, TxReceipt
#include "zeg/rlp.hpp"               // rlp::Item (used by per-auth helper)
#include "zeg/storages.hpp"
#include "zeg/transactions.hpp"
#include "zeg/transient_storage.hpp"

namespace zeg {

class ZiskStateDB final : public evmc::Host {
public:
    // ===== Nested data types =====

    // Snapshot taken by `checkpoint()`, undone by `rollback()`. Bundles
    // the journal's checkpoint with the in-progress receipt's logs
    // size so reverted frames also drop their emitted logs.
    struct Checkpoint {
        Journal::Checkpoint journal_cp;
        size_t              log_count;
    };

    // ===== Constructor =====

    ZiskStateDB(Accounts&             accounts,
                const ConsensusInfo&  consensus,
                const Contracts&      contracts,
                const PreviousBlocks& previous_blocks,
                Storages&             storages);

    // ===== evmc::Host overrides =====
    //
    // Listed in evmc::Host declaration order. Most are direct
    // pass-throughs to the corresponding Accounts/Storages accessor;
    // the execution-driving ones (call, emit_log, access_account,
    // access_storage) do real work and live near the bottom.

    bool account_exists(const evmc::address& addr) const noexcept override;
    evmc::bytes32 get_storage(const evmc::address& addr,
                              const evmc::bytes32& key) const noexcept override;
    evmc_storage_status set_storage(const evmc::address& addr,
                                    const evmc::bytes32& key,
                                    const evmc::bytes32& value) noexcept override;
    evmc::bytes32 get_transient_storage(const evmc::address& addr,
                                        const evmc::bytes32& key) const noexcept override;
    void set_transient_storage(const evmc::address& addr,
                               const evmc::bytes32& key,
                               const evmc::bytes32& value) noexcept override;
    evmc::uint256be get_balance(const evmc::address& addr) const noexcept override;
    size_t get_code_size(const evmc::address& addr) const noexcept override;
    evmc::bytes32 get_code_hash(const evmc::address& addr) const noexcept override;
    size_t copy_code(const evmc::address& addr,
                     size_t offset,
                     uint8_t* buffer,
                     size_t buffer_size) const noexcept override;
    bool selfdestruct(const evmc::address& addr,
                      const evmc::address& beneficiary) noexcept override;
    evmc::Result call(const evmc_message& msg) noexcept override;
    evmc_tx_context get_tx_context() const noexcept override;
    evmc::bytes32 get_block_hash(int64_t block_number) const noexcept override;
    void emit_log(const evmc::address& addr,
                  const uint8_t* data,
                  size_t data_size,
                  const evmc::bytes32 topics[],
                  size_t topics_count) noexcept override;
    evmc_access_status access_account(const evmc::address& addr) noexcept override;
    evmc_access_status access_storage(const evmc::address& addr,
                                      const evmc::bytes32& key) noexcept override;

    // ===== Public methods =====

    // Bytecode slice for `addr`. Empty span when the account has no
    // code (code_hash == keccak256("")). Used by the executor to feed
    // evmone the top-level call's code; not part of the evmc::Host
    // interface (callers below the top level use copy_code instead).
    std::span<const uint8_t> code(const evmc::address& addr) const noexcept;

    // The evmone VM instance ZiskStateDB owns and re-uses for both
    // top-level execution (from main()) and nested calls (from the
    // `call()` override above).
    evmc::VM& vm() noexcept { return vm_; }

    // ----- tx_context plumbing -----
    //
    // The Host's `get_tx_context()` returns a stored snapshot rather
    // than rebuilding from ConsensusInfo on every call. The execute
    // layer populates it: `pre_execute_block` writes the block-level
    // fields once; `process_transactions` updates the per-tx fields
    // (tx_origin, tx_gas_price, …) before each tx.
    void set_tx_context(const evmc_tx_context& ctx) noexcept;

    // ----- journal / revert checkpoint -----
    //
    // Bundles the journal's checkpoint with the current tx's emitted-
    // log count so reverted frames also drop their emitted logs. The
    // mutating Host overrides (`set_storage`, `selfdestruct`, …) log
    // pre-write values via the journal before touching state, so a
    // failed call frame can be reverted cleanly.
    Checkpoint checkpoint() noexcept;
    void       rollback(Checkpoint cp) noexcept;

    // ----- block-output accessors -----
    //
    // Populated by `execute_block` (and the per-tx pipeline inside it).
    // Empty / zero defaults until `execute_block` returns.

    // One TxReceipt per processed tx, in order.
    size_t                     tx_receipt_count() const noexcept { return tx_receipts_.size(); }
    const TxReceipt&           tx_receipt(size_t i) const         { return tx_receipts_[i]; }
    std::span<const TxReceipt> tx_receipts() const noexcept       { return tx_receipts_; }

    // Block-wide aggregated logsBloom — OR of every tx's logs_bloom.
    const std::array<uint8_t, 256>& block_bloom_filter() const noexcept { return block_bloom_filter_; }

    // Canonical receipts trie root (Yellow Paper §4.3.1). Empty trie
    // (no txs) yields the well-known empty-trie root.
    const evmc::bytes32& receipts_root() const noexcept { return receipts_root_; }

    // Cumulative gas used across every tx processed in this block —
    // matches the block header's `gasUsed` field.
    uint64_t gas_used() const noexcept { return cumulative_gas_used_; }

    // Canonical withdrawals trie root (EIP-4895). Empty list yields the
    // well-known empty-trie root.
    const evmc::bytes32& withdrawals_root() const noexcept { return withdrawals_root_; }

    // Total blob gas used by every Type-3 (Blob) tx in the block:
    // num_blobs × GAS_PER_BLOB. Matches the block header's EIP-4844
    // `blobGasUsed` field.
    uint64_t blob_gas_used() const noexcept { return blob_gas_used_; }

    // Per-type Pectra request blobs (EIP-7685). Each entry is one type
    // group, laid out as `type_byte || concatenated_records`:
    //   type 0x00 → deposit requests        (EIP-6110)
    //   type 0x01 → withdrawal requests     (EIP-7002)
    //   type 0x02 → consolidation requests  (EIP-7251)
    // Empty queues add no entry.
    std::span<const std::vector<uint8_t>> requests() const noexcept { return requests_; }

    // EIP-7685 requests_hash: sha256(sha256(req[0]) || sha256(req[1]) ||
    // ...) over the type-prefixed request blobs in `requests_`. Empty
    // list collapses to sha256("") per the EIP.
    const evmc::bytes32& requests_hash() const noexcept { return requests_hash_; }

    // ----- block execution driver -----
    //
    // One-shot entry point that drives the whole block: pre-block
    // system calls, every tx, then post-block side-effects.
    // `transactions` was already parsed up front.
    void execute_block(const Transactions& transactions) noexcept;

private:
    // ===== Private methods =====

    // Move `value` ether from `from` to `to`, logging both pre-write
    // balances to the journal first so a later rollback restores them.
    // No balance check — the EVM has already gated the call on it.
    void transfer_value(const evmc::address& from,
                        const evmc::address& to,
                        const evmc::uint256be& value) noexcept;

    // CREATE-family handler used by `call()` for EVMC_CREATE /
    // EVMC_CREATE2 / EVMC_EOFCREATE. Owns the new-address derivation,
    // sender-nonce bump, EIP-684 collision check, value transfer,
    // init-code execution, and code-hash registration. `cp` is the
    // checkpoint already taken by `call()` so we can roll back on
    // failure of any step.
    evmc::Result call_create(const evmc_message& msg,
                             Checkpoint cp) noexcept;

    // ----- CREATE-family sub-helpers (used by call_create) -----

    // Derive the new contract address per the kind on `msg`. CREATE
    // uses sender + sender_nonce; CREATE2 / EOFCREATE use sender +
    // salt + keccak(init).
    evmc::address derive_create_address(const evmc_message& msg,
                                        uint64_t            sender_nonce_pre,
                                        const uint8_t*      init_code,
                                        std::size_t         init_size) noexcept;

    // EIP-684 collision check + initialize the new account
    // (nonce = 1, value transfer). Returns false on collision. Both
    // mutations are journaled.
    bool init_create_account(const evmc::address& new_addr,
                             const evmc_message&  msg) noexcept;

    // After successful init-code execution, set the new account's
    // code_hash = keccak256(result.output_data). Journaled.
    void register_deployed_code(const evmc::address& new_addr,
                                const evmc::Result&  result) noexcept;

    // Block-execution phase helpers — split out so `execute_block`
    // reads as three clear steps.
    void pre_execute_block ()                                   noexcept;
    void process_transactions(const Transactions& transactions) noexcept;
    void post_execute_block()                                   noexcept;

    // ----- Per-tx pipeline (called in this order by process_transactions) -----
    //
    // Each helper takes the next tx (plus any cross-phase scalar it
    // needs) and may mutate Accounts / Storages / the in-progress
    // receipt directly. `process_transactions` itself is the
    // orchestrator and stays small.

    // Build the per-tx evmc_tx_context from `tx_context_` (block-level
    // fields filled by pre_execute_block) + per-tx fields from `tx`.
    // `blob_hashes` and `initcodes_vec` are scratch buffers the caller
    // owns; pointers into them are written into the returned ctx so
    // they must outlive any subsequent vm_.execute call.
    evmc_tx_context build_per_tx_context(
        const Transactions::View&        tx,
        std::vector<evmc::bytes32>&      blob_hashes,
        std::vector<evmc_tx_initcode>&   initcodes_vec) noexcept;

    // Bump sender nonce, debit upfront gas + blob fee, fatal on
    // insufficient balance. Returns the tx's intrinsic gas (also used
    // as the EVM frame's starting gas budget).
    int64_t apply_pre_evm_accounting(const Transactions::View& tx,
                                     size_t sender_idx) noexcept;

    // Walk the EIP-7702 authorization_list (no-op for non-SetCode
    // txs). For each valid auth, bumps the signer's nonce and writes
    // the 0xef0100 || delegate code_hash on the signer. Returns the
    // accumulated refund (12500 per auth whose signer was non-empty).
    int64_t apply_authorization_list(const Transactions::View& tx) noexcept;

    // Per-auth helper: parse one RLP-encoded authorization entry,
    // verify the signature, look up the signer in the witness, and
    // (on success) bump the signer's nonce + write the 0xef0100 ||
    // delegate code_hash. Returns the refund delta — 12500 if the
    // signer was non-empty before the mutation, else 0; returns 0 on
    // any validity failure (silently skipped per the EIP).
    int64_t process_single_authorization(const rlp::Item& auth_item,
                                         const Transactions::View& tx,
                                         size_t auth_idx) noexcept;

    // Build the top-level evmc_message and dispatch CREATE vs CALL.
    // Caller is responsible for the surrounding checkpoint/rollback.
    evmc::Result execute_top_level_frame(const Transactions::View& tx,
                                         size_t sender_idx,
                                         int64_t intrinsic_gas) noexcept;

    // Post-EVM gas settlement: EIP-3529 refund cap, sender refund,
    // coinbase priority-fee credit. Returns the final tx gas_used.
    uint64_t settle_tx_gas(const Transactions::View& tx,
                           const evmc::Result&       result,
                           size_t                    sender_idx,
                           int64_t                   auth_refund) noexcept;

    // Compute the per-tx logs bloom from the (post-rollback) surviving
    // logs, OR into the block bloom, set the tx's status and cumGas.
    void finalize_receipt(const evmc::Result& result, uint64_t gas_used) noexcept;

    // ----- Per-block post-execution phases (called by post_execute_block) -----

    void credit_withdrawals()                 noexcept;  // EIP-4895
    void collect_deposit_requests()           noexcept;  // EIP-6110
    void collect_withdrawal_requests()        noexcept;  // EIP-7002
    void collect_consolidation_requests()     noexcept;  // EIP-7251

    // Pectra system-call helper used by `pre_execute_block` (EIP-4788
    // beacon roots, EIP-2935 block-hash history) and
    // `post_execute_block` (EIP-7002 withdrawal requests, EIP-7251
    // consolidation requests). Calls `target` from the system address
    // with `calldata` (may be empty — the requests predeploys dequeue
    // on empty calldata), 30M gas, value 0. State changes inside the
    // frame survive (or roll back on revert via the standard checkpoint
    // mechanism). The returned `evmc::Result` gives the caller access
    // to `output_data` for predeploys that return a queue dump.
    evmc::Result system_call(const evmc::address&     target,
                             std::span<const uint8_t> calldata) noexcept;

    // ===== Members =====

    Accounts&             accounts_;
    const ConsensusInfo&  consensus_;
    const Contracts&      contracts_;
    const PreviousBlocks& previous_blocks_;
    Storages&             storages_;

    evmc_tx_context       tx_context_{};
    Journal               journal_{};
    evmc::VM              vm_;
    // EIP-1153 transient storage. Reset at the start of every EVM
    // frame (each tx + each system call) by the call sites that bump
    // tx_counter_. TSTORE writes are journaled so revert restores
    // (or erases) the entry.
    TransientStorage      transient_{};

    // Monotonic counter incremented at the start of each tx in
    // process_transactions. Passed to Storages for per-tx warm/cold
    // and per-tx-original tracking. Starts at 0 so first tx runs
    // with tx_counter_ == 1 > 0 (the never-touched sentinel).
    uint64_t              tx_counter_{0};

    // Per-tx receipts (finalized at end-of-tx; logs filled by emit_log
    // during execution).
    std::vector<TxReceipt>   tx_receipts_{};
    // Cumulative gas used across all processed txs in this block.
    uint64_t                 cumulative_gas_used_{0};
    // OR-aggregation of every tx's logs_bloom; matches the block
    // header's logsBloom field.
    std::array<uint8_t, 256> block_bloom_filter_{};

    // keccak256 of the receipts trie's root RLP. Computed at the end
    // of execute_block from tx_receipts_.
    evmc::bytes32 receipts_root_{};

    // keccak256 of the withdrawals trie's root RLP. Computed at the
    // end of execute_block from consensus_.withdrawals().
    evmc::bytes32 withdrawals_root_{};

    // EIP-4844 blobGasUsed: sum of (num_blobs × GAS_PER_BLOB) across
    // every Type-3 tx processed in this block.
    uint64_t blob_gas_used_{0};

    // EIP-7685 requests collected from the Pectra predeploys (one
    // entry per non-empty request type; entries are type-prefixed).
    std::vector<std::vector<uint8_t>> requests_{};

    // EIP-7685 requests_hash. Computed at the end of execute_block
    // from requests_.
    evmc::bytes32 requests_hash_{};
};

} // namespace zeg

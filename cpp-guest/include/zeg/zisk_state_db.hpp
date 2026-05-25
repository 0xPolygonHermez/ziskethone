// ZiskStateDB — evmc::Host implementation for the ZisK Ethereum guest.
//
// Owns nothing — borrows the five input-stream collections by
// reference from their lifetime-owners (typically constructed at
// main() scope and outliving this object). `Accounts` / `Storages`
// are mutable refs because EVM host setters mutate them;
// `ConsensusInfo` / `Contracts` / `PreviousBlocks` are read-only.
//
// Most Host overrides are direct pass-throughs to the corresponding
// collection's accessors. A handful of methods that depend on
// infrastructure not yet built (transient storage, EVM call re-entry,
// log collector, EIP-2929 access list) abort via zeg::fatal — making
// the gap loud the first time the EVM exercises them.

#pragma once

#include <cstdint>
#include <span>

#include <evmc/evmc.hpp>

#include "zeg/accounts.hpp"
#include "zeg/consensus_info.hpp"
#include "zeg/contracts.hpp"
#include "zeg/journal.hpp"
#include "zeg/previous_blocks.hpp"
#include "zeg/storages.hpp"
#include "zeg/transactions.hpp"

namespace zeg {

class ZiskStateDB final : public evmc::Host {
public:
    ZiskStateDB(Accounts&             accounts,
                const ConsensusInfo&  consensus,
                const Contracts&      contracts,
                const PreviousBlocks& previous_blocks,
                Storages&             storages);

    // ===== evmc::Host interface (evmone re-execution callbacks) =====
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

    // Bytecode slice for `addr`. Empty span when the account has no
    // code (code_hash == keccak256("")). Used by the execute layer to
    // feed evmone the top-level call's code; not part of the evmc::Host
    // interface (callers below the top level use copy_code instead).
    std::span<const uint8_t> code(const evmc::address& addr) const noexcept;

    // The evmone VM instance ZiskStateDB owns and re-uses for both
    // top-level execution (from main()) and nested calls (from the
    // `call()` override below). Exposed so the executor can run the
    // top-level frame against the same VM the Host dispatches against.
    evmc::VM& vm() noexcept { return vm_; }

    // ===== tx_context plumbing =====
    //
    // The Host's `get_tx_context()` returns a stored snapshot rather
    // than rebuilding from ConsensusInfo on every call. The execute
    // layer populates it: `execute_pre_block` writes the block-level
    // fields once; `execute_transactions` updates the per-tx fields
    // (tx_origin, tx_gas_price, …) before each tx.
    void set_tx_context(const evmc_tx_context& ctx) noexcept;

    // ===== journal =====
    //
    // Internal undo log driving `checkpoint()` / `rollback()`. The
    // mutating Host overrides (`set_storage`, `selfdestruct`) log the
    // pre-write value here before touching Accounts/Storages, so a
    // failed call frame can be reverted cleanly.
    Journal::Checkpoint checkpoint() noexcept;
    void                rollback(Journal::Checkpoint cp) noexcept;

    // ===== block execution =====
    //
    // One-shot driver for the whole block: sets the block-level
    // tx_context, runs pre-block system calls, re-executes every tx
    // against evmone, then applies post-block side-effects.
    // `transactions` was already parsed up front.
    void execute_block(const Transactions& transactions) noexcept;

private:
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
                             Journal::Checkpoint cp) noexcept;

    // Block-execution phase helpers — split out so `execute_block`
    // reads as three clear steps. Pre/post will eventually run system
    // contracts (EIP-4788 / 2935 / 7002 / 7251); transactions feeds
    // each parsed envelope into evmone against `*this` as the Host.
    void pre_execute_block ()                                      noexcept;
    void process_transactions(const Transactions& transactions)    noexcept;
    void post_execute_block()                                      noexcept;

    Accounts&             accounts_;
    const ConsensusInfo&  consensus_;
    const Contracts&      contracts_;
    const PreviousBlocks& previous_blocks_;
    Storages&             storages_;

    evmc_tx_context       tx_context_{};
    Journal               journal_{};
    evmc::VM              vm_;
};

} // namespace zeg

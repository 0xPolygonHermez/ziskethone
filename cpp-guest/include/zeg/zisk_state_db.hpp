// ZiskStateDB — evmc::Host implementation for the ZisK Ethereum guest.
//
// Owns the entire state needed to statelessly re-execute a block: accounts
// (balance, nonce, codeHash), storage values, and contract bytecodes, all
// parsed from a single input stream in the constructor.
//
// The public API takes a `const uint8_t*& cursor` (reference to a pointer
// into the input buffer) and advances it past every byte consumed, so the
// caller can chain calls without tracking offsets manually. Every advance
// is a multiple of 8 bytes so the cursor stays 8-byte aligned and typed
// pointer casts on the input buffer remain valid.

#pragma once

#include <cstdint>
#include <optional>

#include <evmc/evmc.hpp>

#include "zeg/accounts.hpp"
#include "zeg/contracts.hpp"
#include "zeg/storages.hpp"

namespace zeg {

class ZiskStateDB final : public evmc::Host {
public:
    // Parse accounts, storage values, contract bytecodes, and previous-block
    // headers from the stream in that order. `cursor` is advanced past every
    // byte consumed.
    explicit ZiskStateDB(const uint8_t*& cursor);

    // Walk the proof bytes from `cursor` and compute the parent block's
    // (pre-execution) state root. `cursor` is advanced past the consumed
    // proof bytes.
    evmc::bytes32 calculateOldStateRoot(const uint8_t*& cursor);

    // Walk the proof bytes from `cursor` and compute the post-execution
    // state root. `cursor` is advanced past the consumed proof bytes.
    evmc::bytes32 calculateNewStateRoot(const uint8_t*& cursor);

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

private:
    std::optional<Contracts> contracts_;
    std::optional<Accounts>  accounts_;
    std::optional<Storages>  storages_;

    // Each parser advances `cursor` past the bytes it consumed (multiple of 8).
    void parseContracts(const uint8_t*& cursor);
    void parseAccounts(const uint8_t*& cursor);
    void parseStorageValues(const uint8_t*& cursor);
    void parsePrevBlocks(const uint8_t*& cursor);
};

} // namespace zeg

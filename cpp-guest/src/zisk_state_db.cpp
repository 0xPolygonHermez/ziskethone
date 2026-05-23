#include "zeg/zisk_state_db.hpp"

#include "zeg/state_root.hpp"
#include "zeg/stream.hpp"

namespace zeg {

// ===== Constructor & public API =====

ZiskStateDB::ZiskStateDB(const uint8_t*& cursor) {
    parseContracts(cursor);
    parseAccounts(cursor);
    parseStorageValues(cursor);
    parsePrevBlocks(cursor);
}

evmc::bytes32 ZiskStateDB::calculateOldStateRoot(const uint8_t*& cursor) {
    // Pre-execution root: mods_ are empty in Accounts/Storages, so the
    // dirty-aware accessors return originals.
    return calculate_state_root(cursor, *accounts_, *storages_);
}

evmc::bytes32 ZiskStateDB::calculateNewStateRoot(const uint8_t*& cursor) {
    (void)cursor;
    return {};
}

// ===== Private parsers =====

void ZiskStateDB::parseAccounts(const uint8_t*& cursor) {
    // Zero-copy: hand the start-pointer and count to the Accounts module,
    // which keeps pointers-into-stream for the originals and a parallel
    // dirty-tracked side table for modifications.
    const uint64_t count = read_u64_le(cursor);
    const uint8_t* records = cursor;
    accounts_.emplace(count, records);
    cursor += count * Accounts::kRecordSize;
}

void ZiskStateDB::parseStorageValues(const uint8_t*& cursor) {
    // Zero-copy: hand the start-pointer and count to the Storages module.
    const uint64_t count = read_u64_le(cursor);
    const uint8_t* records = cursor;
    storages_.emplace(count, records);
    cursor += count * Storages::kRecordSize;
}

void ZiskStateDB::parseContracts(const uint8_t*& cursor) {
    // Variable-length records: Contracts walks them itself and advances
    // `cursor` past every byte consumed (each record is u64-aligned).
    const uint64_t count = read_u64_le(cursor);
    contracts_.emplace(count, cursor);
}

void ZiskStateDB::parsePrevBlocks(const uint8_t*& cursor) {
    (void)cursor;
}

// ===== evmc::Host overrides (all stubs for now) =====

bool ZiskStateDB::account_exists(const evmc::address&) const noexcept {
    return false;
}

evmc::bytes32 ZiskStateDB::get_storage(const evmc::address&,
                                      const evmc::bytes32&) const noexcept {
    return {};
}

evmc_storage_status ZiskStateDB::set_storage(const evmc::address&,
                                             const evmc::bytes32&,
                                             const evmc::bytes32&) noexcept {
    return EVMC_STORAGE_ASSIGNED;
}

evmc::bytes32 ZiskStateDB::get_transient_storage(const evmc::address&,
                                                 const evmc::bytes32&) const noexcept {
    return {};
}

void ZiskStateDB::set_transient_storage(const evmc::address&,
                                        const evmc::bytes32&,
                                        const evmc::bytes32&) noexcept {
}

evmc::uint256be ZiskStateDB::get_balance(const evmc::address&) const noexcept {
    return {};
}

size_t ZiskStateDB::get_code_size(const evmc::address&) const noexcept {
    return 0;
}

evmc::bytes32 ZiskStateDB::get_code_hash(const evmc::address&) const noexcept {
    return {};
}

size_t ZiskStateDB::copy_code(const evmc::address&,
                              size_t,
                              uint8_t*,
                              size_t) const noexcept {
    return 0;
}

bool ZiskStateDB::selfdestruct(const evmc::address&,
                               const evmc::address&) noexcept {
    return false;
}

evmc::Result ZiskStateDB::call(const evmc_message&) noexcept {
    return evmc::Result{EVMC_FAILURE, 0, 0, nullptr, 0};
}

evmc_tx_context ZiskStateDB::get_tx_context() const noexcept {
    return {};
}

evmc::bytes32 ZiskStateDB::get_block_hash(int64_t) const noexcept {
    return {};
}

void ZiskStateDB::emit_log(const evmc::address&,
                           const uint8_t*,
                           size_t,
                           const evmc::bytes32[],
                           size_t) noexcept {
}

evmc_access_status ZiskStateDB::access_account(const evmc::address&) noexcept {
    return EVMC_ACCESS_COLD;
}

evmc_access_status ZiskStateDB::access_storage(const evmc::address&,
                                               const evmc::bytes32&) noexcept {
    return EVMC_ACCESS_COLD;
}

} // namespace zeg

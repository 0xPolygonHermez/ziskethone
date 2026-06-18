#pragma once
// storage.cpp — persistent & transient storage opcodes (SLOAD 0x54, SSTORE 0x55,
// TLOAD 0x5c, TSTORE 0x5d).
//
// These call back into the host (ZiskStateDB) through the evmc C interface for
// the account whose storage is being accessed — the message recipient. Keys and
// values are evmc_bytes32, i.e. 32 big-endian bytes; the stack stores little-
// endian integers, so they are byteswapped in/out via u256_from_be / u256_to_be.
//
// Gas matches evmone for Berlin..Prague (EIP-2929 warm/cold, EIP-2200 net
// metering, EIP-3529 refunds, EIP-1706 sentry). SSTORE returns its
// {cost, refund} from set_storage's classification; the refund accumulates on
// EvmState::gas_refund (the host applies the transaction cap).

#include "detail.hpp"

#include <cstring>

namespace zevm {

namespace storage_ops {

constexpr int64_t WARM_STORAGE_READ_COST = 100;
constexpr int64_t COLD_SLOAD_COST        = 2100;
constexpr int64_t SSTORE_SENTRY_GAS      = 2300;   // EIP-1706

// Net-metering SSTORE schedule for London..Prague, derived from the spec
// constants exactly as evmone builds its table (so refunds can't be mistyped).
constexpr int64_t SS_SET    = 20000;                       // 0 -> nonzero
constexpr int64_t SS_RESET  = 5000 - COLD_SLOAD_COST;      // 2900 (cold surcharge split out)
constexpr int64_t SS_CLEAR  = 4800;                        // EIP-3529 clear refund

struct SStoreCost { int64_t cost; int64_t refund; };

// Indexed by evmc_storage_status (0..8): ASSIGNED, ADDED, DELETED, MODIFIED,
// DELETED_ADDED, MODIFIED_DELETED, DELETED_RESTORED, ADDED_DELETED,
// MODIFIED_RESTORED.
constexpr SStoreCost SSTORE_COST[] = {
    {WARM_STORAGE_READ_COST, 0},                                          // ASSIGNED
    {SS_SET, 0},                                                          // ADDED
    {SS_RESET, SS_CLEAR},                                                 // DELETED
    {SS_RESET, 0},                                                        // MODIFIED
    {WARM_STORAGE_READ_COST, -SS_CLEAR},                                  // DELETED_ADDED
    {WARM_STORAGE_READ_COST, SS_CLEAR},                                   // MODIFIED_DELETED
    {WARM_STORAGE_READ_COST, SS_RESET - WARM_STORAGE_READ_COST - SS_CLEAR}, // DELETED_RESTORED
    {WARM_STORAGE_READ_COST, SS_SET - WARM_STORAGE_READ_COST},            // ADDED_DELETED
    {WARM_STORAGE_READ_COST, SS_RESET - WARM_STORAGE_READ_COST},          // MODIFIED_RESTORED
};

// The 32 big-endian bytes of stack slot `i` (its LE integer value byteswapped to
// the on-wire evmc_bytes32 form the host expects for keys/values).
inline evmc_bytes32 slot_bytes(const EvmState& s, uint32_t i) {
    evmc_bytes32 b;
    u256_to_be(s.stack[i], b.bytes);
    return b;
}

// 0x54 SLOAD — push storage[key]. Warm (100) base + cold surcharge (EIP-2929).
bool op_sload(EvmState& s, Regs& R) {
    if (R.gas < WARM_STORAGE_READ_COST) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_STORAGE_READ_COST;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const evmc_bytes32 key = slot_bytes(s, R.sp);
    if (s.rev >= EVMC_BERLIN &&
        s.host->access_storage(s.context, &s.evmcMsg->recipient, &key) == EVMC_ACCESS_COLD) {
        const int64_t extra = COLD_SLOAD_COST - WARM_STORAGE_READ_COST;
        if (R.gas < extra) { s.status = EVMC_OUT_OF_GAS; return false; }
        R.gas -= extra;
    }
    const evmc_bytes32 v = s.host->get_storage(s.context, &s.evmcMsg->recipient, &key);
    s.stack[R.sp] = u256_from_be(v.bytes);  // BE value -> LE slot
    ++R.pc;
    return true;
}

// 0x55 SSTORE — storage[key] = value (EIP-2200/2929/3529 metering + refunds).
bool op_sstore(EvmState& s, Regs& R) {
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (s.evmcMsg->flags & EVMC_STATIC) { s.status = EVMC_STATIC_MODE_VIOLATION; return false; }
    if (s.rev >= EVMC_ISTANBUL && R.gas <= SSTORE_SENTRY_GAS) {
        s.status = EVMC_OUT_OF_GAS;  // EIP-1706 sentry
        return false;
    }
    const evmc_bytes32 key   = slot_bytes(s, R.sp);
    const evmc_bytes32 value = slot_bytes(s, R.sp + 1);

    int64_t cold = 0;
    if (s.rev >= EVMC_BERLIN &&
        s.host->access_storage(s.context, &s.evmcMsg->recipient, &key) == EVMC_ACCESS_COLD) {
        cold = COLD_SLOAD_COST;
    }
    const evmc_storage_status st =
        s.host->set_storage(s.context, &s.evmcMsg->recipient, &key, &value);
    const SStoreCost sc = SSTORE_COST[st];
    const int64_t cost = sc.cost + cold;
    if (R.gas < cost) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= cost;
    s.gas_refund += sc.refund;

    R.sp += 2;  // pop key and value
    ++R.pc;
    return true;
}

// 0x5c TLOAD — push transient_storage[key] (EIP-1153). Flat 100 gas.
bool op_tload(EvmState& s, Regs& R) {
    if (R.gas < WARM_STORAGE_READ_COST) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_STORAGE_READ_COST;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const evmc_bytes32 key = slot_bytes(s, R.sp);
    const evmc_bytes32 v =
        s.host->get_transient_storage(s.context, &s.evmcMsg->recipient, &key);
    s.stack[R.sp] = u256_from_be(v.bytes);  // BE value -> LE slot
    ++R.pc;
    return true;
}

// 0x5d TSTORE — transient_storage[key] = value (EIP-1153). Flat 100 gas.
bool op_tstore(EvmState& s, Regs& R) {
    if (R.gas < WARM_STORAGE_READ_COST) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_STORAGE_READ_COST;
    if (s.evmcMsg->flags & EVMC_STATIC) { s.status = EVMC_STATIC_MODE_VIOLATION; return false; }
    if (stack_depth(R.sp) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const evmc_bytes32 key   = slot_bytes(s, R.sp);
    const evmc_bytes32 value = slot_bytes(s, R.sp + 1);
    s.host->set_transient_storage(s.context, &s.evmcMsg->recipient, &key, &value);

    R.sp += 2;  // pop key and value
    ++R.pc;
    return true;
}

}  // namespace


}  // namespace zevm

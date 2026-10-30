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

struct SStoreCost { int64_t cost; int64_t refund; };

// Per-revision SSTORE schedule, mirroring evmone's storage_cost_spec table
// (lib/evmone/instructions_storage.cpp). The clear refund and the warm/reset
// bases changed across forks; a single London+ table over-charged pre-London
// (Berlin's storage-clear refund is 15000, not EIP-3529's 4800 — a 10200 gas
// delta that showed up on every fork_Berlin state test that SSTOREs a value).
//   net_cost — EIP-2200 net metering active (false = legacy full-cost schedule)
//   warm     — warm-access base (200/800 pre-Berlin, 100 = warm_storage_read on Berlin+)
//   set/reset— 0->nonzero / nonzero->nonzero base (cold surcharge added separately on Berlin+)
//   clear    — storage-deletion refund R_sclear (15000 pre-London, 4800 EIP-3529)
//   cold     — cold-slot surcharge (EIP-2929; 0 before Berlin)
// Amsterdam (EIP-8038) prices the write separately: set = reset = warm +
// STORAGE_WRITE, the clear refund scales with it, and the cold surcharge is
// only the access part (2000), as the reset no longer nets out 2100.
struct StorageCostSpec { bool net_cost; int64_t warm; int64_t set; int64_t reset; int64_t clear; int64_t cold; };

constexpr StorageCostSpec storage_spec(evmc_revision rev) {
    if (rev >= EVMC_AMSTERDAM) {
        constexpr int64_t write = WARM_STORAGE_READ_COST + STORAGE_WRITE;
        return {true, WARM_STORAGE_READ_COST, write, write,
                (STORAGE_WRITE + COLD_SLOAD_COST) * 4800 / 5000,
                COLD_SLOAD_COST - WARM_STORAGE_READ_COST};
    }
    if (rev >= EVMC_LONDON)         return {true, WARM_STORAGE_READ_COST, 20000, 5000 - COLD_SLOAD_COST, 4800, COLD_SLOAD_COST};
    if (rev == EVMC_BERLIN)         return {true, WARM_STORAGE_READ_COST, 20000, 5000 - COLD_SLOAD_COST, 15000, COLD_SLOAD_COST};
    if (rev == EVMC_ISTANBUL)       return {true, 800, 20000, 5000, 15000, 0};
    return {false, 200, 20000, 5000, 15000, 0};  // legacy: Frontier..Petersburg
}

// SSTORE {cost, refund} for a storage-update status under the active revision's
// schedule. Faithful to evmone's sstore_costs table build (both legacy and net).
constexpr SStoreCost sstore_cost(evmc_revision rev, evmc_storage_status st) {
    const StorageCostSpec c = storage_spec(rev);
    const int64_t W = c.warm;
    if (!c.net_cost) {  // legacy full-cost schedule (pre-Constantinople / Petersburg)
        switch (st) {
            case EVMC_STORAGE_ADDED:             return {c.set,   0};
            case EVMC_STORAGE_DELETED:           return {c.reset, c.clear};
            case EVMC_STORAGE_MODIFIED:          return {c.reset, 0};
            case EVMC_STORAGE_ASSIGNED:          return {c.reset, 0};        // = MODIFIED
            case EVMC_STORAGE_DELETED_ADDED:     return {c.set,   0};        // = ADDED
            case EVMC_STORAGE_MODIFIED_DELETED:  return {c.reset, c.clear};  // = DELETED
            case EVMC_STORAGE_DELETED_RESTORED:  return {c.set,   0};        // = ADDED
            case EVMC_STORAGE_ADDED_DELETED:     return {c.reset, c.clear};  // = DELETED
            case EVMC_STORAGE_MODIFIED_RESTORED: return {c.reset, 0};        // = MODIFIED
        }
    } else {  // net metering (EIP-2200/2929/3529)
        switch (st) {
            case EVMC_STORAGE_ASSIGNED:          return {W, 0};
            case EVMC_STORAGE_ADDED:             return {c.set,   0};
            case EVMC_STORAGE_DELETED:           return {c.reset, c.clear};
            case EVMC_STORAGE_MODIFIED:          return {c.reset, 0};
            case EVMC_STORAGE_DELETED_ADDED:     return {W, -c.clear};
            case EVMC_STORAGE_MODIFIED_DELETED:  return {W, c.clear};
            case EVMC_STORAGE_DELETED_RESTORED:  return {W, c.reset - W - c.clear};
            case EVMC_STORAGE_ADDED_DELETED:     return {W, c.set - W};
            case EVMC_STORAGE_MODIFIED_RESTORED: return {W, c.reset - W};
        }
    }
    return {W, 0};
}

// The 32 big-endian bytes of stack slot `i` (its LE integer value byteswapped to
// the on-wire evmc_bytes32 form the host expects for keys/values).
inline evmc_bytes32 slot_bytes(const U256* i) {
    evmc_bytes32 b;
    u256_to_be(i[0], b.bytes);
    return b;
}

// 0x54 SLOAD — push storage[key]. Warm (100) base + cold surcharge (EIP-2929).
bool op_sload(EvmState& s, Regs& R) {
    if (R.gas < WARM_STORAGE_READ_COST) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_STORAGE_READ_COST;
    if (depth_lt(R, 1)) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const evmc_bytes32 key = slot_bytes(R.top);
    if (s.rev >= EVMC_BERLIN &&
        s.host->access_storage(s.context, &s.evmcMsg->recipient, &key) == EVMC_ACCESS_COLD) {
        const int64_t extra = COLD_SLOAD_COST - WARM_STORAGE_READ_COST;
        if (R.gas < extra) { s.status = EVMC_OUT_OF_GAS; return false; }
        R.gas -= extra;
    }
    const evmc_bytes32 v = s.host->get_storage(s.context, &s.evmcMsg->recipient, &key);
    R.top[0] = u256_from_be(v.bytes);  // BE value -> LE slot
    return true;
}

// 0x55 SSTORE — storage[key] = value (EIP-2200/2929/3529 metering + refunds).
bool op_sstore(EvmState& s, Regs& R) {
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (s.evmcMsg->flags & EVMC_STATIC) { s.status = EVMC_STATIC_MODE_VIOLATION; return false; }
    if (s.rev >= EVMC_ISTANBUL && R.gas <= SSTORE_SENTRY_GAS) {
        s.status = EVMC_OUT_OF_GAS;  // EIP-1706 sentry
        return false;
    }
    const evmc_bytes32 key   = slot_bytes(R.top);
    const evmc_bytes32 value = slot_bytes(R.top + 1);

    int64_t cold = 0;
    if (s.rev >= EVMC_BERLIN &&
        s.host->access_storage(s.context, &s.evmcMsg->recipient, &key) == EVMC_ACCESS_COLD) {
        cold = storage_spec(s.rev).cold;
    }
    const evmc_storage_status st =
        s.host->set_storage(s.context, &s.evmcMsg->recipient, &key, &value);
    const SStoreCost sc = sstore_cost(s.rev, st);
    const int64_t cost = sc.cost + cold;
    if (R.gas < cost) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= cost;
    // EIP-8037 (Amsterdam): allocating a slot (0 -> x) costs state gas; setting
    // it back to 0 in the same tx gives it back.
    if (s.rev >= EVMC_AMSTERDAM) {
        if (st == EVMC_STORAGE_ADDED) {
            int64_t g = R.gas;
            if (!state_gas_charge(s, g, STORAGE_SET_STATE_GAS)) {
                s.status = EVMC_OUT_OF_GAS; return false;
            }
            R.gas = g;
        } else if (st == EVMC_STORAGE_ADDED_DELETED) {
            int64_t g = R.gas;
            state_gas_refill(s, g, STORAGE_SET_STATE_GAS);
            R.gas = g;
        }
    }
    s.gas_refund += sc.refund;

    return true;
}

// 0x5c TLOAD — push transient_storage[key] (EIP-1153). Flat 100 gas.
bool op_tload(EvmState& s, Regs& R) {
    if (R.gas < WARM_STORAGE_READ_COST) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_STORAGE_READ_COST;
    if (depth_lt(R, 1)) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const evmc_bytes32 key = slot_bytes(R.top);
    const evmc_bytes32 v =
        s.host->get_transient_storage(s.context, &s.evmcMsg->recipient, &key);
    R.top[0] = u256_from_be(v.bytes);  // BE value -> LE slot
    return true;
}

// 0x5d TSTORE — transient_storage[key] = value (EIP-1153). Flat 100 gas.
bool op_tstore(EvmState& s, Regs& R) {
    if (R.gas < WARM_STORAGE_READ_COST) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_STORAGE_READ_COST;
    if (s.evmcMsg->flags & EVMC_STATIC) { s.status = EVMC_STATIC_MODE_VIOLATION; return false; }
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const evmc_bytes32 key   = slot_bytes(R.top);
    const evmc_bytes32 value = slot_bytes(R.top + 1);
    s.host->set_transient_storage(s.context, &s.evmcMsg->recipient, &key, &value);

    return true;
}

}  // namespace


}  // namespace zevm

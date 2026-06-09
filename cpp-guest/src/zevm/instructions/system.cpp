// system.cpp — the call/create subsystem: CALL (0xf1), CALLCODE (0xf2),
// DELEGATECALL (0xf4), STATICCALL (0xfa), CREATE (0xf0), CREATE2 (0xf5); the
// halting/output opcodes RETURN (0xf3) and REVERT (0xfd); the return-data
// opcodes RETURNDATASIZE (0x3d) and RETURNDATACOPY (0x3e); and INVALID (0xfe).
//
// zevm is the interpreter: it pops/caps the gas, charges every call/create cost
// (EIP-2929 account access, value, new-account, args/return memory, EIP-3860
// init-code cost, the EIP-150 63/64 cap, the 2300 stipend), builds the child
// evmc_message, and invokes host->call. The host (ZiskStateDB) runs the child
// frame — for CREATE it also derives the address, executes the init code, and
// charges the code deposit — and returns gas_left + output (+ create_address).
// Leftover gas and the child's refund flow back here.
//
// NOTE (deferred): EIP-7702 delegation-target resolution (get_target_address) is
// not handled — code_address is the call target as-is.

#include "detail.hpp"

#include <cstring>

#include "evm_mem.hpp"

namespace zevm {

namespace {

constexpr int64_t WARM_ACCESS         = 100;    // warm_storage_read_cost (call base)
constexpr int64_t COLD_ACCOUNT_ACCESS = 2600;   // EIP-2929
constexpr int64_t CALL_VALUE_COST     = 9000;
constexpr int64_t ACCOUNT_CREATION    = 25000;
constexpr int64_t CALL_STIPEND        = 2300;

constexpr int64_t GAS_CREATE          = 32000;  // CREATE / CREATE2 base
constexpr uint64_t MAX_INITCODE_SIZE  = 0xC000; // EIP-3860 (2 * 24576)
constexpr int64_t INITCODE_WORD_COST  = 2;      // EIP-3860 per 32-byte word
constexpr int64_t KECCAK_WORD_COST    = 6;      // CREATE2 hashes the init code

// Unsigned compare of two big-endian 256-bit words (memcmp works: MSB first).
inline bool be_lt(const evmc_uint256be& a, const evmc_uint256be& b) {
    return std::memcmp(a.bytes, b.bytes, 32) < 0;
}

// Shared implementation of the four call opcodes.
//   has_value      — CALL/CALLCODE take a value arg (DELEGATECALL/STATICCALL don't)
//   static_forced  — STATICCALL forces the child into static mode
bool call_impl(EvmState& s, evmc_call_kind kind, bool has_value, bool static_forced) {
    const uint32_t nargs = has_value ? 7u : 6u;

    if (s.gas < WARM_ACCESS) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= WARM_ACCESS;
    if (stack_depth(s) < nargs) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    const uint32_t sp       = s.stackPointer;
    const uint32_t iGas     = sp;
    const uint32_t iDst     = sp + 1;
    const uint32_t iVal     = sp + 2;                 // only when has_value
    const uint32_t b        = has_value ? sp + 3 : sp + 2;
    const uint32_t iInOff   = b;
    const uint32_t iInSize  = b + 1;
    const uint32_t iOutOff  = b + 2;
    const uint32_t iOutSize = b + 3;
    const uint32_t iResult  = iOutSize;               // last popped slot -> pushed result

    // ----- read operands (captured before any host call / overwrite) -----
    to_le(s, iGas);
    int64_t req_gas;
    {
        const U256& g = s.stack[iGas];
        req_gas = ((g.limbs[1] | g.limbs[2] | g.limbs[3]) != 0 ||
                   g.limbs[0] > static_cast<uint64_t>(INT64_MAX))
                      ? INT64_MAX
                      : static_cast<int64_t>(g.limbs[0]);
    }

    to_be(s, iDst);  // address = low 20 big-endian bytes of the word
    evmc_address dst;
    std::memcpy(dst.bytes, reinterpret_cast<const uint8_t*>(&s.stack[iDst]) + 12, 20);

    bool nonzero_value = false;
    evmc_uint256be value_be{};
    if (has_value) {
        nonzero_value = !u256_is_zero(s.stack[iVal]);
        to_be(s, iVal);
        std::memcpy(value_be.bytes, &s.stack[iVal], 32);
    }

    to_le(s, iInOff); to_le(s, iInSize); to_le(s, iOutOff); to_le(s, iOutSize);
    const uint64_t in_off   = mem_arg(s.stack[iInOff]);
    const uint64_t in_size  = mem_arg(s.stack[iInSize]);
    const uint64_t out_off  = mem_arg(s.stack[iOutOff]);
    const uint64_t out_size = mem_arg(s.stack[iOutSize]);

    // Supersede any prior return data (releasing it if it was heap-owned).
    if (s.returnDataOwner.release) s.returnDataOwner.release(&s.returnDataOwner);
    s.returnDataOwner = evmc_result{};

    // "light" failure (insufficient balance / depth): push 0 and continue.
    auto finish_light = [&]() {
        s.stack[iResult] = U256{};
        s.stackBE[iResult] = kLE;
        s.stackPointer = iResult;
        ++s.pc;
        return true;
    };

    // ----- gas: account access (EIP-2929) -----
    if (s.rev >= EVMC_BERLIN &&
        s.host->access_account(s.context, &dst) == EVMC_ACCESS_COLD) {
        const int64_t extra = COLD_ACCOUNT_ACCESS - WARM_ACCESS;  // 2500
        if (s.gas < extra) { s.status = EVMC_OUT_OF_GAS; return false; }
        s.gas -= extra;
    }

    // ----- gas: value transfer (+ static-mode violation) -----
    if (has_value) {
        if (kind == EVMC_CALL && nonzero_value && (s.evmcMsg->flags & EVMC_STATIC)) {
            s.status = EVMC_STATIC_MODE_VIOLATION;
            return false;
        }
        if (nonzero_value) {
            if (s.gas < CALL_VALUE_COST) { s.status = EVMC_OUT_OF_GAS; return false; }
            s.gas -= CALL_VALUE_COST;
        }
    }

    // ----- gas: new-account creation (CALL with value to a missing account) -----
    if (kind == EVMC_CALL && nonzero_value &&
        !s.host->account_exists(s.context, &dst)) {
        if (s.gas < ACCOUNT_CREATION) { s.status = EVMC_OUT_OF_GAS; return false; }
        s.gas -= ACCOUNT_CREATION;
    }

    // ----- gas: memory expansion for the input and output windows -----
    if (EVMMem::expand(static_cast<size_t>(in_off), static_cast<size_t>(in_size), &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    if (EVMMem::expand(static_cast<size_t>(out_off), static_cast<size_t>(out_size), &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }

    // ----- EIP-150 "all but one 64th" cap on the gas passed to the child -----
    int64_t call_gas = req_gas;
    const int64_t cap = s.gas - s.gas / 64;
    if (call_gas > cap) call_gas = cap;

    // ----- build the child message -----
    evmc_message msg{};
    msg.kind         = kind;
    msg.flags        = static_forced ? uint32_t{EVMC_STATIC} : (s.evmcMsg->flags & EVMC_STATIC);
    msg.depth        = s.evmcMsg->depth + 1;
    msg.gas          = call_gas;
    msg.recipient    = (kind == EVMC_CALL) ? dst : s.evmcMsg->recipient;   // CALL/STATICCALL -> dst
    msg.code_address = dst;
    msg.sender       = (kind == EVMC_DELEGATECALL) ? s.evmcMsg->sender : s.evmcMsg->recipient;
    if (kind == EVMC_DELEGATECALL) msg.value = s.evmcMsg->value;
    else if (has_value)            msg.value = value_be;                   // STATICCALL keeps 0
    if (in_size > 0) {
        msg.input_data = EVMMem::data(static_cast<size_t>(in_off));
        msg.input_size = static_cast<size_t>(in_size);
    }

    // ----- stipend + caller-balance light failure -----
    if (has_value && nonzero_value) {
        msg.gas += CALL_STIPEND;
        s.gas   += CALL_STIPEND;
        const evmc_uint256be bal = s.host->get_balance(s.context, &s.evmcMsg->recipient);
        if (be_lt(bal, value_be)) return finish_light();
    }

    // ----- depth limit -----
    if (s.evmcMsg->depth >= 1024) return finish_light();

    // ----- run the child frame via the host -----
    evmc_result r = s.host->call(s.context, &msg);

    s.stack[iResult] = (r.status_code == EVMC_SUCCESS) ? U256{{1, 0, 0, 0}} : U256{};
    s.stackBE[iResult] = kLE;

    if (const size_t copy = std::min<size_t>(static_cast<size_t>(out_size), r.output_size); copy > 0)
        std::memcpy(EVMMem::data(static_cast<size_t>(out_off)), r.output_data, copy);

    // Hold the result as return data (its output_data/output_size back the
    // RETURNDATA* opcodes): a zevm child's output lives in the other EVMMem zone,
    // a precompile's is heap-owned — either way it's released when the next call
    // supersedes it or the frame ends.
    s.returnDataOwner = r;

    s.gas        -= (msg.gas - r.gas_left);  // reclaim the child's leftover gas
    s.gas_refund += r.gas_refund;

    s.stackPointer = iResult;
    ++s.pc;
    return true;
}

bool op_call(EvmState& s)         { return call_impl(s, EVMC_CALL,         /*has_value=*/true,  /*static=*/false); }
bool op_callcode(EvmState& s)     { return call_impl(s, EVMC_CALLCODE,     /*has_value=*/true,  /*static=*/false); }
bool op_delegatecall(EvmState& s) { return call_impl(s, EVMC_DELEGATECALL, /*has_value=*/false, /*static=*/false); }
bool op_staticcall(EvmState& s)   { return call_impl(s, EVMC_CALL,         /*has_value=*/false, /*static=*/true); }

// Shared implementation of CREATE / CREATE2. The host (ZiskStateDB::call_create)
// derives the new address, runs the init code, and charges the code deposit;
// here we charge what the interpreter owns (base, init-code memory, EIP-3860
// size + word cost, CREATE2's keccak word cost, the 63/64 cap), build the
// message, and push the created address (0 on failure).
bool create_impl(EvmState& s, evmc_call_kind kind) {
    const bool     is2   = (kind == EVMC_CREATE2);
    const uint32_t nargs = is2 ? 4u : 3u;

    if (s.gas < GAS_CREATE) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_CREATE;
    if (stack_depth(s) < nargs) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (s.evmcMsg->flags & EVMC_STATIC) { s.status = EVMC_STATIC_MODE_VIOLATION; return false; }

    const uint32_t sp      = s.stackPointer;
    const uint32_t iVal    = sp;
    const uint32_t iOff    = sp + 1;
    const uint32_t iSize   = sp + 2;
    const uint32_t iSalt   = sp + 3;          // CREATE2 only
    const uint32_t iResult = is2 ? sp + 3 : sp + 2;

    const bool nonzero_value = !u256_is_zero(s.stack[iVal]);
    to_be(s, iVal);
    evmc_uint256be value_be;
    std::memcpy(value_be.bytes, &s.stack[iVal], 32);

    to_le(s, iOff);
    to_le(s, iSize);
    const uint64_t off  = mem_arg(s.stack[iOff]);
    const uint64_t size = mem_arg(s.stack[iSize]);

    evmc_bytes32 salt{};
    if (is2) {
        to_be(s, iSalt);
        std::memcpy(salt.bytes, &s.stack[iSalt], 32);
    }

    // Supersede any prior return data (releasing it if it was heap-owned).
    if (s.returnDataOwner.release) s.returnDataOwner.release(&s.returnDataOwner);
    s.returnDataOwner = evmc_result{};

    auto finish_fail = [&]() {  // "light" failure (depth / balance): push 0, continue
        s.stack[iResult] = U256{};
        s.stackBE[iResult] = kLE;
        s.stackPointer = iResult;
        ++s.pc;
        return true;
    };

    // init-code memory expansion
    if (EVMMem::expand(static_cast<size_t>(off), static_cast<size_t>(size), &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    // EIP-3860: cap init-code size, charge per word (+ CREATE2 keccak per word)
    if (size > MAX_INITCODE_SIZE) { s.status = EVMC_OUT_OF_GAS; return false; }
    const int64_t word_cost = INITCODE_WORD_COST + (is2 ? KECCAK_WORD_COST : 0);
    const int64_t init_cost = static_cast<int64_t>((size + 31) / 32) * word_cost;
    if (s.gas < init_cost) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= init_cost;

    if (s.evmcMsg->depth >= 1024) return finish_fail();
    if (nonzero_value) {
        const evmc_uint256be bal = s.host->get_balance(s.context, &s.evmcMsg->recipient);
        if (be_lt(bal, value_be)) return finish_fail();
    }

    // EIP-150 cap on the gas handed to the init frame.
    evmc_message msg{};
    msg.kind   = kind;
    msg.gas    = s.gas - s.gas / 64;
    msg.sender = s.evmcMsg->recipient;
    msg.depth  = s.evmcMsg->depth + 1;
    msg.value  = value_be;
    if (is2) msg.create2_salt = salt;
    if (size > 0) {
        msg.input_data = EVMMem::data(static_cast<size_t>(off));
        msg.input_size = static_cast<size_t>(size);
    }

    evmc_result r = s.host->call(s.context, &msg);
    s.gas        -= (msg.gas - r.gas_left);
    s.gas_refund += r.gas_refund;
    s.returnDataOwner = r;  // keep revert output (empty on success) as return data

    if (r.status_code == EVMC_SUCCESS) {
        // the 20-byte address, right-aligned in the 256-bit word -> BE form
        U256 a{};
        std::memcpy(reinterpret_cast<uint8_t*>(&a) + 12, r.create_address.bytes, 20);
        s.stack[iResult] = a;
        s.stackBE[iResult] = kBE;
    } else {
        s.stack[iResult] = U256{};
        s.stackBE[iResult] = kLE;
    }
    s.stackPointer = iResult;
    ++s.pc;
    return true;
}

bool op_create(EvmState& s)  { return create_impl(s, EVMC_CREATE); }
bool op_create2(EvmState& s) { return create_impl(s, EVMC_CREATE2); }

// RETURN (success) / REVERT — set the frame's output window and halt.
bool return_impl(EvmState& s, evmc_status_code st) {
    if (stack_depth(s) < 2) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    const uint64_t off  = mem_arg(s.stack[s.stackPointer]);
    const uint64_t size = mem_arg(s.stack[s.stackPointer + 1]);
    if (size > 0) {
        if (EVMMem::expand(static_cast<size_t>(off), static_cast<size_t>(size), &s.gas) != MemError::Ok) {
            s.status = EVMC_OUT_OF_GAS;
            return false;
        }
        s.output_offset = static_cast<size_t>(off);
        s.output_size   = static_cast<size_t>(size);
    } else {
        s.output_size = 0;
    }
    s.status = st;
    return false;  // halt the frame
}

bool op_return(EvmState& s) { return return_impl(s, EVMC_SUCCESS); }
bool op_revert(EvmState& s) { return return_impl(s, EVMC_REVERT); }

// 0x3d RETURNDATASIZE — size of the last sub-call's output.
bool op_returndatasize(EvmState& s) {
    if (s.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_BASE;
    if (stack_depth(s) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --s.stackPointer;
    s.stack[s.stackPointer] = U256{{static_cast<uint64_t>(s.returnDataOwner.output_size), 0, 0, 0}};
    s.stackBE[s.stackPointer] = kLE;
    ++s.pc;
    return true;
}

// 0x3e RETURNDATACOPY — copy return data into memory (EIP-211 bounds-checked).
bool op_returndatacopy(EvmState& s) {
    if (s.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= GAS_VERYLOW;
    if (stack_depth(s) < 3) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    to_le(s, s.stackPointer);
    to_le(s, s.stackPointer + 1);
    to_le(s, s.stackPointer + 2);
    const uint64_t mem_off = mem_arg(s.stack[s.stackPointer]);
    const uint64_t ret_off = mem_arg(s.stack[s.stackPointer + 1]);
    const uint64_t size    = mem_arg(s.stack[s.stackPointer + 2]);

    if (EVMMem::expand(static_cast<size_t>(mem_off), static_cast<size_t>(size), &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const uint64_t rds = s.returnDataOwner.output_size;
    if (ret_off > rds || size > rds - ret_off) {  // EIP-211: must be fully in bounds
        s.status = EVMC_INVALID_MEMORY_ACCESS;
        return false;
    }
    const int64_t cost = 3 * static_cast<int64_t>((size + 31) / 32);  // 3 per word
    if (s.gas < cost) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= cost;

    if (size > 0)
        std::memcpy(EVMMem::data(static_cast<size_t>(mem_off)),
                    s.returnDataOwner.output_data + ret_off, static_cast<size_t>(size));
    s.stackPointer += 3;
    ++s.pc;
    return true;
}

// 0xfe INVALID — designated invalid opcode; halts with failure.
bool op_invalid(EvmState& s) {
    s.status = EVMC_INVALID_INSTRUCTION;
    return false;
}

}  // namespace

void register_system(InstrTable& t, evmc_revision rev) {
    t[0xf0] = &op_create;
    t[0xf1] = &op_call;
    t[0xf2] = &op_callcode;
    t[0xf3] = &op_return;
    t[0xfe] = &op_invalid;
    if (rev >= EVMC_HOMESTEAD)  // EIP-7
        t[0xf4] = &op_delegatecall;
    if (rev >= EVMC_BYZANTIUM) {  // EIP-211 (RETURNDATA*), EIP-214 (STATICCALL), EIP-140 (REVERT)
        t[0x3d] = &op_returndatasize;
        t[0x3e] = &op_returndatacopy;
        t[0xfa] = &op_staticcall;
        t[0xfd] = &op_revert;
    }
    if (rev >= EVMC_CONSTANTINOPLE)  // EIP-1014
        t[0xf5] = &op_create2;
}

}  // namespace zevm

#pragma once
// system.cpp — the call/create subsystem: CALL (0xf1), CALLCODE (0xf2),
// DELEGATECALL (0xf4), STATICCALL (0xfa), CREATE (0xf0), CREATE2 (0xf5); the
// halting/output opcodes RETURN (0xf3), REVERT (0xfd) and SELFDESTRUCT (0xff);
// the return-data opcodes RETURNDATASIZE (0x3d) and RETURNDATACOPY (0x3e); and
// INVALID (0xfe).
//
// zevm is the interpreter: it pops/caps the gas, charges every call/create cost
// (EIP-2929 account access, value, new-account, args/return memory, EIP-3860
// init-code cost, the EIP-150 63/64 cap, the 2300 stipend), builds the child
// evmc_message, and invokes host->call. The host (ZiskStateDB) runs the child
// frame — for CREATE it also derives the address, executes the init code, and
// charges the code deposit — and returns gas_left + output (+ create_address).
// Leftover gas and the child's refund flow back here.
//
// EIP-7702: a call whose target is a delegated EOA (code == 0xef0100 || address)
// runs the delegate's code (code_address moves to the delegate, recipient stays
// the EOA), charging the delegate's account-access gas — see call_impl.

#include "detail.hpp"

#include <cstring>

#include "evm_mem.hpp"

namespace zevm {

namespace system_ops {

constexpr int64_t WARM_ACCESS         = 100;    // warm_storage_read_cost (call base)
constexpr int64_t COLD_ACCOUNT_ACCESS = 2600;   // EIP-2929
constexpr int64_t CALL_VALUE_COST     = 9000;
constexpr int64_t ACCOUNT_CREATION    = 25000;
constexpr int64_t CALL_STIPEND        = 2300;

constexpr int64_t GAS_CREATE          = 32000;  // CREATE / CREATE2 base
constexpr uint64_t MAX_INITCODE_SIZE  = 0xC000; // EIP-3860 (2 * 24576)
constexpr int64_t INITCODE_WORD_COST  = 2;      // EIP-3860 per 32-byte word
constexpr int64_t KECCAK_WORD_COST    = 6;      // CREATE2 hashes the init code

constexpr int64_t SELFDESTRUCT_GAS    = 5000;   // SELFDESTRUCT base (Tangerine+)
constexpr int64_t SELFDESTRUCT_REFUND = 24000;  // pre-London only

// Unsigned compare of two big-endian 256-bit words (memcmp works: MSB first).
inline bool be_lt(const evmc_uint256be& a, const evmc_uint256be& b) {
    return std::memcmp(a.bytes, b.bytes, 32) < 0;
}

// Shared implementation of the four call opcodes.
//   has_value      — CALL/CALLCODE take a value arg (DELEGATECALL/STATICCALL don't)
//   static_forced  — STATICCALL forces the child into static mode
bool call_impl(EvmState& s, Regs& R, evmc_call_kind kind, bool has_value, bool static_forced) {
    const size_t nargs = has_value ? 7u : 6u;

    if (R.gas < WARM_ACCESS) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_ACCESS;
    if (depth_lt(R, nargs)) { s.status = EVMC_STACK_UNDERFLOW; return false; }

    U256* const sp       = R.top;
    U256* const iGas     = sp;
    U256* const iDst     = sp + 1;
    U256* const iVal     = sp + 2;                 // only when has_value
    U256* const b        = has_value ? sp + 3 : sp + 2;
    U256* const iInOff   = b;
    U256* const iInSize  = b + 1;
    U256* const iOutOff  = b + 2;
    U256* const iOutSize = b + 3;
    U256* const iResult  = iOutSize;               // last popped slot -> pushed result

    // ----- read operands (captured before any host call / overwrite) -----
    int64_t req_gas;
    {
        const U256 g = ld_le(iGas);
        req_gas = ((g.limbs[1] | g.limbs[2] | g.limbs[3]) != 0 ||
                   g.limbs[0] > static_cast<uint64_t>(INT64_MAX))
                      ? INT64_MAX
                      : static_cast<int64_t>(g.limbs[0]);
    }

    const evmc_address dst = addr_from_slot(iDst[0]);  // low 20 bytes of the value

    bool nonzero_value = false;
    evmc_uint256be value_be{};
    if (has_value) {
        nonzero_value = !u256_is_zero(iVal[0]);
        u256_to_be(iVal[0], value_be.bytes);  // LE slot -> BE wire value
    }

    const uint64_t in_off   = mem_arg(iInOff[0]);
    const uint64_t in_size  = mem_arg(iInSize[0]);
    const uint64_t out_off  = mem_arg(iOutOff[0]);
    const uint64_t out_size = mem_arg(iOutSize[0]);

    // Supersede any prior return data (releasing it if it was heap-owned).
    if (s.returnDataOwner.release) s.returnDataOwner.release(&s.returnDataOwner);
    s.returnDataOwner = evmc_result{};

    // "light" failure (insufficient balance / depth): push 0 and continue.
    auto finish_light = [&]() {
        iResult[0] = U256{};  // zero is BE-agnostic
        R.top = iResult;
        ++R.pc;
        return true;
    };

    // ----- gas: account access (EIP-2929) -----
    if (s.rev >= EVMC_BERLIN &&
        s.host->access_account(s.context, &dst) == EVMC_ACCESS_COLD) {
        const int64_t extra = COLD_ACCOUNT_ACCESS - WARM_ACCESS;  // 2500
        if (R.gas < extra) { s.status = EVMC_OUT_OF_GAS; return false; }
        R.gas -= extra;
    }

    // ----- gas: value transfer (+ static-mode violation) -----
    if (has_value) {
        if (kind == EVMC_CALL && nonzero_value && (s.evmcMsg->flags & EVMC_STATIC)) {
            s.status = EVMC_STATIC_MODE_VIOLATION;
            return false;
        }
        if (nonzero_value) {
            if (R.gas < CALL_VALUE_COST) { s.status = EVMC_OUT_OF_GAS; return false; }
            R.gas -= CALL_VALUE_COST;
        }
    }

    // ----- gas: new-account creation (CALL with value to a missing account) -----
    if (kind == EVMC_CALL && nonzero_value &&
        !s.host->account_exists(s.context, &dst)) {
        if (R.gas < ACCOUNT_CREATION) { s.status = EVMC_OUT_OF_GAS; return false; }
        R.gas -= ACCOUNT_CREATION;
    }

    // ----- EIP-7702 (Prague+): resolve a delegated call target -----
    // If the callee's code is a delegation designator (0xef0100 || address), run
    // the delegate's code instead — charging the delegate's EIP-2929 account
    // access (2600 cold / 100 warm) on top of the target's own access above. The
    // child still uses `recipient` for storage/context; only `code_address` moves
    // to the delegate. (EXTCODE* are unaffected: they see the designator.)
    evmc_address code_addr = dst;
    if (s.rev >= EVMC_PRAGUE) {
        uint8_t desig[23];  // 0xef 0x01 0x00 + 20-byte delegate address
        const size_t n = s.host->copy_code(s.context, &dst, 0, desig, sizeof(desig));
        if (n == sizeof(desig) && desig[0] == 0xef && desig[1] == 0x01 && desig[2] == 0x00) {
            std::memcpy(code_addr.bytes, desig + 3, 20);
            const int64_t dcost =
                s.host->access_account(s.context, &code_addr) == EVMC_ACCESS_COLD
                    ? COLD_ACCOUNT_ACCESS : WARM_ACCESS;
            if (R.gas < dcost) { s.status = EVMC_OUT_OF_GAS; return false; }
            R.gas -= dcost;
        }
    }

    // ----- gas: memory expansion for the input and output windows -----
    if (mem_expand(R, static_cast<size_t>(in_off), static_cast<size_t>(in_size)) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    if (mem_expand(R, static_cast<size_t>(out_off), static_cast<size_t>(out_size)) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }

    // ----- EIP-150 "all but one 64th" cap on the gas passed to the child -----
    int64_t call_gas = req_gas;
    const int64_t cap = R.gas - R.gas / 64;
    if (call_gas > cap) call_gas = cap;

    // ----- build the child message -----
    evmc_message msg{};
    msg.kind         = kind;
    msg.flags        = static_forced ? uint32_t{EVMC_STATIC} : (s.evmcMsg->flags & EVMC_STATIC);
    msg.depth        = s.evmcMsg->depth + 1;
    msg.gas          = call_gas;
    msg.recipient    = (kind == EVMC_CALL) ? dst : s.evmcMsg->recipient;   // CALL/STATICCALL -> dst
    msg.code_address = code_addr;                                          // delegate when 7702-delegated
    if (std::memcmp(dst.bytes, code_addr.bytes, sizeof(dst.bytes)) != 0)
        msg.flags |= EVMC_DELEGATED;
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
        R.gas   += CALL_STIPEND;
        const evmc_uint256be bal = s.host->get_balance(s.context, &s.evmcMsg->recipient);
        if (be_lt(bal, value_be)) return finish_light();
    }

    // ----- depth limit -----
    if (s.evmcMsg->depth >= 1024) return finish_light();

    // ----- run the child frame via the host -----
    evmc_result r = s.host->call(s.context, &msg);

    st_le(iResult, (r.status_code == EVMC_SUCCESS) ? U256{{1, 0, 0, 0}} : U256{});

    if (const size_t copy = std::min<size_t>(static_cast<size_t>(out_size), r.output_size); copy > 0)
        std::memcpy(EVMMem::data(static_cast<size_t>(out_off)), r.output_data, copy);

    // Hold the result as return data (its output_data/output_size back the
    // RETURNDATA* opcodes): a zevm child's output lives in the other EVMMem zone,
    // a precompile's is heap-owned — either way it's released when the next call
    // supersedes it or the frame ends.
    s.returnDataOwner = r;

    R.gas        -= (msg.gas - r.gas_left);  // reclaim the child's leftover gas
    s.gas_refund += r.gas_refund;

    R.top = iResult;
    ++R.pc;
    return true;
}

bool op_call(EvmState& s, Regs& R)         { return call_impl(s, R, EVMC_CALL,         /*has_value=*/true,  /*static=*/false); }
bool op_callcode(EvmState& s, Regs& R)     { return call_impl(s, R, EVMC_CALLCODE,     /*has_value=*/true,  /*static=*/false); }
bool op_delegatecall(EvmState& s, Regs& R) { return call_impl(s, R, EVMC_DELEGATECALL, /*has_value=*/false, /*static=*/false); }
bool op_staticcall(EvmState& s, Regs& R)   { return call_impl(s, R, EVMC_CALL,         /*has_value=*/false, /*static=*/true); }

// Shared implementation of CREATE / CREATE2. The host (ZiskStateDB::call_create)
// derives the new address, runs the init code, and charges the code deposit;
// here we charge what the interpreter owns (base, init-code memory, EIP-3860
// size + word cost, CREATE2's keccak word cost, the 63/64 cap), build the
// message, and push the created address (0 on failure).
bool create_impl(EvmState& s, Regs& R, evmc_call_kind kind) {
    const bool     is2   = (kind == EVMC_CREATE2);
    const size_t nargs = is2 ? 4u : 3u;

    if (R.gas < GAS_CREATE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_CREATE;
    if (depth_lt(R, nargs)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (s.evmcMsg->flags & EVMC_STATIC) { s.status = EVMC_STATIC_MODE_VIOLATION; return false; }

    U256* const sp      = R.top;
    U256* const iVal    = sp;
    U256* const iOff    = sp + 1;
    U256* const iSize   = sp + 2;
    U256* const iSalt   = sp + 3;          // CREATE2 only
    U256* const iResult = is2 ? sp + 3 : sp + 2;

    const bool nonzero_value = !u256_is_zero(iVal[0]);
    evmc_uint256be value_be;
    u256_to_be(iVal[0], value_be.bytes);  // LE slot -> BE wire value

    const uint64_t off  = mem_arg(iOff[0]);
    const uint64_t size = mem_arg(iSize[0]);

    evmc_bytes32 salt{};
    if (is2)
        u256_to_be(iSalt[0], salt.bytes);  // LE slot -> BE wire salt

    // Supersede any prior return data (releasing it if it was heap-owned).
    if (s.returnDataOwner.release) s.returnDataOwner.release(&s.returnDataOwner);
    s.returnDataOwner = evmc_result{};

    auto finish_fail = [&]() {  // "light" failure (depth / balance): push 0, continue
        iResult[0] = U256{};  // zero is BE-agnostic
        R.top = iResult;
        ++R.pc;
        return true;
    };

    // init-code memory expansion
    if (mem_expand(R, static_cast<size_t>(off), static_cast<size_t>(size)) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    // EIP-3860 (Shanghai+): cap init-code size and add 2 gas/word. The CREATE2
    // keccak word cost (6/word) applies on its own since Constantinople, so
    // pre-Shanghai CREATE pays nothing here and CREATE2 pays only the 6/word.
    const bool eip3860 = s.rev >= EVMC_SHANGHAI;
    if (eip3860 && size > MAX_INITCODE_SIZE) { s.status = EVMC_OUT_OF_GAS; return false; }
    const int64_t word_cost = (is2 ? KECCAK_WORD_COST : 0) + (eip3860 ? INITCODE_WORD_COST : 0);
    if (word_cost != 0) {
        const int64_t init_cost = num_words(size) * word_cost;
        if (R.gas < init_cost) { s.status = EVMC_OUT_OF_GAS; return false; }
        R.gas -= init_cost;
    }

    if (s.evmcMsg->depth >= 1024) return finish_fail();
    if (nonzero_value) {
        const evmc_uint256be bal = s.host->get_balance(s.context, &s.evmcMsg->recipient);
        if (be_lt(bal, value_be)) return finish_fail();
    }

    // EIP-150 cap on the gas handed to the init frame.
    evmc_message msg{};
    msg.kind   = kind;
    msg.gas    = R.gas - R.gas / 64;
    msg.sender = s.evmcMsg->recipient;
    msg.depth  = s.evmcMsg->depth + 1;
    msg.value  = value_be;
    if (is2) msg.create2_salt = salt;
    if (size > 0) {
        msg.input_data = EVMMem::data(static_cast<size_t>(off));
        msg.input_size = static_cast<size_t>(size);
    }

    evmc_result r = s.host->call(s.context, &msg);
    R.gas        -= (msg.gas - r.gas_left);
    s.gas_refund += r.gas_refund;
    s.returnDataOwner = r;  // keep revert output (empty on success) as return data

    if (r.status_code == EVMC_SUCCESS) {
        iResult[0] = slot_from_address(r.create_address);  // 20-byte address -> LE slot
    } else {
        iResult[0] = U256{};  // zero is BE-agnostic
    }
    R.top = iResult;
    ++R.pc;
    return true;
}

bool op_create(EvmState& s, Regs& R)  { return create_impl(s, R, EVMC_CREATE); }
bool op_create2(EvmState& s, Regs& R) { return create_impl(s, R, EVMC_CREATE2); }

// RETURN (success) / REVERT — set the frame's output window and halt.
bool return_impl(EvmState& s, Regs& R, evmc_status_code st) {
    if (depth_lt(R, 2)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const uint64_t off  = mem_arg(R.top[0]);
    const uint64_t size = mem_arg(R.top[1]);
    if (size > 0) {
        if (mem_expand(R, static_cast<size_t>(off), static_cast<size_t>(size)) != MemError::Ok) {
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

bool op_return(EvmState& s, Regs& R) { return return_impl(s, R, EVMC_SUCCESS); }
bool op_revert(EvmState& s, Regs& R) { return return_impl(s, R, EVMC_REVERT); }

// 0x3d RETURNDATASIZE — size of the last sub-call's output.
bool op_returndatasize(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    if (stack_full(s, R.top)) { s.status = EVMC_STACK_OVERFLOW; return false; }
    st_le(R.top - 1, U256{{static_cast<uint64_t>(s.returnDataOwner.output_size), 0, 0, 0}});
    return true;
}

// 0x3e RETURNDATACOPY — copy return data into memory (EIP-211 bounds-checked).
bool op_returndatacopy(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (depth_lt(R, 3)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const uint64_t mem_off = mem_arg(R.top[0]);
    const uint64_t ret_off = mem_arg(R.top[1]);
    const uint64_t size    = mem_arg(R.top[2]);

    if (mem_expand(R, static_cast<size_t>(mem_off), static_cast<size_t>(size)) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS;
        return false;
    }
    const uint64_t rds = s.returnDataOwner.output_size;
    if (ret_off > rds || size > rds - ret_off) {  // EIP-211: must be fully in bounds
        s.status = EVMC_INVALID_MEMORY_ACCESS;
        return false;
    }
    const int64_t cost = 3 * static_cast<int64_t>((size + 31) / 32);  // 3 per word
    if (R.gas < cost) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= cost;

    if (size > 0)
        std::memcpy(EVMMem::data(static_cast<size_t>(mem_off)),
                    s.returnDataOwner.output_data + ret_off, static_cast<size_t>(size));
    return true;
}

// 0xfe INVALID — designated invalid opcode; halts with failure.
bool op_invalid(EvmState& s, Regs& R) {
    s.status = EVMC_INVALID_INSTRUCTION;
    return false;
}

// 0xff SELFDESTRUCT — transfer the account's balance to the beneficiary and halt.
// Deletion itself is host-side (EIP-6780: only if the account was created in this
// tx); the interpreter just charges gas and calls host->selfdestruct.
bool op_selfdestruct(EvmState& s, Regs& R) {
    if (R.gas < SELFDESTRUCT_GAS) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= SELFDESTRUCT_GAS;
    if (depth_lt(R, 1)) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (s.evmcMsg->flags & EVMC_STATIC) { s.status = EVMC_STATIC_MODE_VIOLATION; return false; }

    const evmc_address ben = addr_from_slot(R.top[0]);  // low 20 bytes of the value

    // Cold beneficiary access (Berlin+): the full 2600 (no warm base for SELFDESTRUCT).
    if (s.rev >= EVMC_BERLIN &&
        s.host->access_account(s.context, &ben) == EVMC_ACCESS_COLD) {
        if (R.gas < COLD_ACCOUNT_ACCESS) { s.status = EVMC_OUT_OF_GAS; return false; }
        R.gas -= COLD_ACCOUNT_ACCESS;
    }
    // New-account surcharge: charged when the account has balance to send and the
    // beneficiary does not yet exist.
    const evmc_uint256be bal = s.host->get_balance(s.context, &s.evmcMsg->recipient);
    bool bal_nonzero = false;
    for (int i = 0; i < 32; ++i)
        if (bal.bytes[i] != 0) { bal_nonzero = true; break; }
    if (bal_nonzero && !s.host->account_exists(s.context, &ben)) {
        if (R.gas < ACCOUNT_CREATION) { s.status = EVMC_OUT_OF_GAS; return false; }
        R.gas -= ACCOUNT_CREATION;
    }

    const bool first = s.host->selfdestruct(s.context, &s.evmcMsg->recipient, &ben);
    if (first && s.rev < EVMC_LONDON) s.gas_refund += SELFDESTRUCT_REFUND;

    s.status = EVMC_SUCCESS;
    return false;  // halt the frame
}

}  // namespace


}  // namespace zevm

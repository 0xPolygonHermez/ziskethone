#pragma once
// env.cpp — execution-environment & block-context opcodes (0x30..0x4a, except
// RETURNDATASIZE/RETURNDATACOPY 0x3d/0x3e which live in system.cpp): ADDRESS,
// BALANCE, ORIGIN, CALLER, CALLVALUE, CALLDATA*, CODE*, GASPRICE, EXTCODE*,
// EXTCODEHASH, BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, PREVRANDAO, GASLIMIT,
// CHAINID, SELFBALANCE, BASEFEE, BLOBHASH, BLOBBASEFEE.
//
// Values come from the frame's message (recipient/sender/value/input/code), the
// host's get_tx_context (origin, block fields), or per-account host calls
// (balance/code size/hash, with EIP-2929 cold/warm access gas). The stack stores
// little-endian integers: addresses and 256-bit wire values arrive big-endian and
// are byteswapped in (u256_from_be / slot_from_address); plain integers (sizes,
// block number/timestamp/gas limit) go in directly via st_le.

#include "detail.hpp"

#include <algorithm>
#include <cstring>

#include "evm_mem.hpp"

namespace zevm {

namespace env_ops {

constexpr int64_t WARM_ACCESS    = 100;    // EIP-2929 warm account access (base)
constexpr int64_t COLD_EXTRA     = 2500;   // EIP-2929 cold account surcharge
constexpr int64_t GAS_BLOCKHASH  = 20;

// ----- push helpers (overflow-checked); return false on stack overflow -----

inline bool push_u64(EvmState& s, Regs& R, uint64_t v) {
    if (stack_depth(R.sp) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.sp;
    st_le(s, R.sp, U256{{v, 0, 0, 0}});  // integer -> little-endian slot
    return true;
}

inline bool push_be32(EvmState& s, Regs& R, const uint8_t* be) {  // 32 big-endian bytes
    if (stack_depth(R.sp) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.sp;
    s.stack[R.sp] = u256_from_be(be);  // BE wire bytes -> LE slot
    return true;
}

inline bool push_address(EvmState& s, Regs& R, const evmc_address& a) {  // 20 bytes, right-aligned
    if (stack_depth(R.sp) >= kStackLimit) { s.status = EVMC_STACK_OVERFLOW; return false; }
    --R.sp;
    s.stack[R.sp] = slot_from_address(a);
    return true;
}

// The address operand in stack slot `i`: the low 20 big-endian bytes of its value.
inline evmc_address addr_arg(EvmState& s, uint32_t i) {
    return addr_from_slot(s.stack[i]);
}

// EIP-2929 cold-account surcharge (Berlin+). Returns false on out-of-gas.
inline bool charge_account_access(EvmState& s, Regs& R, const evmc_address& addr) {
    if (s.rev >= EVMC_BERLIN &&
        s.host->access_account(s.context, &addr) == EVMC_ACCESS_COLD) {
        if (R.gas < COLD_EXTRA) { s.status = EVMC_OUT_OF_GAS; return false; }
        R.gas -= COLD_EXTRA;
    }
    return true;
}

// Copy `size` bytes from `data[srcOff..]` (length dataLen) into memory at `dst`,
// zero-padding past the source. Memory must already be grown to cover the window.
inline void copy_into_mem(uint64_t dst, uint64_t size, const uint8_t* data,
                          uint64_t dataLen, uint64_t srcOff) {
    if (size == 0) return;
    uint8_t* mem = EVMMem::data(static_cast<size_t>(dst));
    const uint64_t begin  = srcOff < dataLen ? srcOff : dataLen;
    const uint64_t avail  = dataLen - begin;
    const uint64_t copy_n = avail < size ? avail : size;
    if (copy_n > 0) std::memcpy(mem, data + begin, static_cast<size_t>(copy_n));
    if (size > copy_n) std::memset(mem + copy_n, 0, static_cast<size_t>(size - copy_n));
}

// Shared body of CALLDATACOPY/CODECOPY: pop (dst, src, size), expand, charge
// copy cost, copy from `data`.
inline bool data_copy(EvmState& s, Regs& R, const uint8_t* data, uint64_t dataLen) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 3) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const uint32_t sp = R.sp;
    const uint64_t dst  = mem_arg(s.stack[sp]);
    const uint64_t src  = mem_arg(s.stack[sp + 1]);
    const uint64_t size = mem_arg(s.stack[sp + 2]);
    if (mem_expand(s, R, static_cast<size_t>(dst), static_cast<size_t>(size)) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    const int64_t cc = copy_cost(size);
    if (R.gas < cc) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= cc;
    copy_into_mem(dst, size, data, dataLen, src);
    R.sp += 3;
    ++R.pc;
    return true;
}

// ----- simple context pushes (gas 2 unless noted) -----

bool op_address(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    if (!push_address(s, R, s.evmcMsg->recipient)) return false;
    ++R.pc; return true;
}
bool op_caller(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    if (!push_address(s, R, s.evmcMsg->sender)) return false;
    ++R.pc; return true;
}
bool op_callvalue(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    if (!push_be32(s, R, s.evmcMsg->value.bytes)) return false;
    ++R.pc; return true;
}
bool op_origin(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    if (!push_address(s, R, tx.tx_origin)) return false;
    ++R.pc; return true;
}
bool op_gasprice(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    if (!push_be32(s, R, tx.tx_gas_price.bytes)) return false;
    ++R.pc; return true;
}
bool op_coinbase(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    if (!push_address(s, R, tx.block_coinbase)) return false;
    ++R.pc; return true;
}
bool op_timestamp(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    if (!push_u64(s, R, static_cast<uint64_t>(tx.block_timestamp))) return false;
    ++R.pc; return true;
}
bool op_number(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    if (!push_u64(s, R, static_cast<uint64_t>(tx.block_number))) return false;
    ++R.pc; return true;
}
bool op_prevrandao(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    if (!push_be32(s, R, tx.block_prev_randao.bytes)) return false;
    ++R.pc; return true;
}
bool op_gaslimit(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    if (!push_u64(s, R, static_cast<uint64_t>(tx.block_gas_limit))) return false;
    ++R.pc; return true;
}
bool op_chainid(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    if (!push_be32(s, R, tx.chain_id.bytes)) return false;
    ++R.pc; return true;
}
bool op_basefee(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    if (!push_be32(s, R, tx.block_base_fee.bytes)) return false;
    ++R.pc; return true;
}
bool op_blobbasefee(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    if (!push_be32(s, R, tx.blob_base_fee.bytes)) return false;
    ++R.pc; return true;
}
bool op_calldatasize(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    if (!push_u64(s, R, s.evmcMsg->input_size)) return false;
    ++R.pc; return true;
}
bool op_codesize(EvmState& s, Regs& R) {
    if (R.gas < GAS_BASE) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BASE;
    if (!push_u64(s, R, s.codeSize)) return false;
    ++R.pc; return true;
}

// 0x47 SELFBALANCE — balance of the executing account; flat 5, no access cost.
bool op_selfbalance(EvmState& s, Regs& R) {
    if (R.gas < GAS_LOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_LOW;
    const evmc_uint256be bal = s.host->get_balance(s.context, &s.evmcMsg->recipient);
    if (!push_be32(s, R, bal.bytes)) return false;
    ++R.pc; return true;
}

// 0x35 CALLDATALOAD — 32 bytes of calldata at the top index (zero-padded), BE.
bool op_calldataload(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const uint32_t i = R.sp;
    const uint64_t idx        = mem_arg(s.stack[i]);
    const uint64_t input_size = s.evmcMsg->input_size;
    uint8_t buf[32] = {};
    if (idx < input_size) {
        const size_t begin = static_cast<size_t>(idx);
        const size_t n     = std::min<size_t>(32, static_cast<size_t>(input_size) - begin);
        std::memcpy(buf, s.evmcMsg->input_data + begin, n);
    }
    s.stack[i] = u256_from_be(buf);  // calldata BE bytes -> LE slot
    ++R.pc; return true;
}

// 0x37 CALLDATACOPY / 0x39 CODECOPY.
bool op_calldatacopy(EvmState& s, Regs& R) {
    return data_copy(s, R, s.evmcMsg->input_data, s.evmcMsg->input_size);
}
bool op_codecopy(EvmState& s, Regs& R) {
    return data_copy(s, R, s.code, s.codeSize);
}

// ----- per-account opcodes (EIP-2929 cold/warm) -----

// 0x31 BALANCE.
bool op_balance(EvmState& s, Regs& R) {
    if (R.gas < WARM_ACCESS) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_ACCESS;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const uint32_t i = R.sp;
    const evmc_address addr = addr_arg(s, i);
    if (!charge_account_access(s, R, addr)) return false;
    const evmc_uint256be bal = s.host->get_balance(s.context, &addr);
    s.stack[i] = u256_from_be(bal.bytes);  // BE balance -> LE slot
    ++R.pc; return true;
}

// 0x3b EXTCODESIZE.
bool op_extcodesize(EvmState& s, Regs& R) {
    if (R.gas < WARM_ACCESS) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_ACCESS;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const uint32_t i = R.sp;
    const evmc_address addr = addr_arg(s, i);
    if (!charge_account_access(s, R, addr)) return false;
    st_le(s, i, U256{{s.host->get_code_size(s.context, &addr), 0, 0, 0}});
    ++R.pc; return true;
}

// 0x3f EXTCODEHASH (Constantinople).
bool op_extcodehash(EvmState& s, Regs& R) {
    if (R.gas < WARM_ACCESS) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_ACCESS;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const uint32_t i = R.sp;
    const evmc_address addr = addr_arg(s, i);
    if (!charge_account_access(s, R, addr)) return false;
    const evmc_bytes32 h = s.host->get_code_hash(s.context, &addr);
    s.stack[i] = u256_from_be(h.bytes);  // BE code hash -> LE slot
    ++R.pc; return true;
}

// 0x3c EXTCODECOPY — copy external code into memory; cold surcharge after the
// memory/copy gas (evmone order), then host->copy_code + zero-pad.
bool op_extcodecopy(EvmState& s, Regs& R) {
    if (R.gas < WARM_ACCESS) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= WARM_ACCESS;
    if (stack_depth(R.sp) < 4) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const uint32_t sp = R.sp;
    const evmc_address addr = addr_arg(s, sp);  // top
    const uint64_t dst  = mem_arg(s.stack[sp + 1]);
    const uint64_t src  = mem_arg(s.stack[sp + 2]);
    const uint64_t size = mem_arg(s.stack[sp + 3]);
    if (mem_expand(s, R, static_cast<size_t>(dst), static_cast<size_t>(size)) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    const int64_t cc = copy_cost(size);
    if (R.gas < cc) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= cc;
    if (!charge_account_access(s, R, addr)) return false;
    if (size != 0) {
        uint8_t* mem = EVMMem::data(static_cast<size_t>(dst));
        const size_t copied =
            s.host->copy_code(s.context, &addr, static_cast<size_t>(src), mem, static_cast<size_t>(size));
        if (static_cast<size_t>(size) > copied)
            std::memset(mem + copied, 0, static_cast<size_t>(size) - copied);
    }
    R.sp += 4;
    ++R.pc; return true;
}

// 0x40 BLOCKHASH — hash of one of the last 256 blocks, else 0.
bool op_blockhash(EvmState& s, Regs& R) {
    if (R.gas < GAS_BLOCKHASH) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_BLOCKHASH;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const uint32_t i = R.sp;
    const U256 v = ld_le(s, i);
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    const int64_t upper = tx.block_number;
    const int64_t lower = upper > 256 ? upper - 256 : 0;
    evmc_bytes32 h{};
    if ((v.limbs[1] | v.limbs[2] | v.limbs[3]) == 0 &&
        v.limbs[0] < static_cast<uint64_t>(upper) &&
        static_cast<int64_t>(v.limbs[0]) >= lower) {
        h = s.host->get_block_hash(s.context, static_cast<int64_t>(v.limbs[0]));
    }
    s.stack[i] = u256_from_be(h.bytes);  // BE block hash -> LE slot
    ++R.pc; return true;
}

// 0x49 BLOBHASH (Cancun) — versioned hash of blob `index`, else 0.
bool op_blobhash(EvmState& s, Regs& R) {
    if (R.gas < GAS_VERYLOW) { s.status = EVMC_OUT_OF_GAS; return false; }
    R.gas -= GAS_VERYLOW;
    if (stack_depth(R.sp) < 1) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    const uint32_t i = R.sp;
    const U256 v = ld_le(s, i);
    const evmc_tx_context tx = s.host->get_tx_context(s.context);
    evmc_bytes32 h{};
    if ((v.limbs[1] | v.limbs[2] | v.limbs[3]) == 0 && v.limbs[0] < tx.blob_hashes_count)
        h = tx.blob_hashes[static_cast<size_t>(v.limbs[0])];
    s.stack[i] = u256_from_be(h.bytes);  // BE versioned hash -> LE slot
    ++R.pc; return true;
}

}  // namespace


}  // namespace zevm

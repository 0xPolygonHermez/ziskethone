#pragma once
// log.cpp — logging opcodes LOG0..LOG4 (0xa0..0xa4).
//
// LOGn pops a memory window (offset, size) and n topics, then emits a log for
// the message recipient via host->emit_log. Gas: a base of 375*(1+n) (the
// per-opcode cost, folding in the 375-per-topic charge) + 8 per data byte +
// memory expansion. Disallowed in static mode. Topics are 256-bit words passed
// as evmc_bytes32 (big-endian), byteswapped out of the little-endian slots.

#include "detail.hpp"

#include <cstring>

#include "evm_mem.hpp"

namespace zevm {

namespace log_ops {

constexpr int64_t GAS_LOG     = 375;  // per LOG + per topic (G_log / G_logtopic)
constexpr int64_t GAS_LOGDATA = 8;    // per byte of logged data

// Shared implementation of LOG0..LOG4 (n = number of topics, 0..4).
bool log_impl(EvmState& s, unsigned n) {
    const int64_t base = GAS_LOG * static_cast<int64_t>(1 + n);
    if (s.gas < base) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= base;
    if (stack_depth(s) < 2u + n) { s.status = EVMC_STACK_UNDERFLOW; return false; }
    if (s.evmcMsg->flags & EVMC_STATIC) { s.status = EVMC_STATIC_MODE_VIOLATION; return false; }

    const uint32_t sp = s.stackPointer;
    const uint64_t off  = mem_arg(s.stack[sp]);
    const uint64_t size = mem_arg(s.stack[sp + 1]);

    if (EVMMem::expand(static_cast<size_t>(off), static_cast<size_t>(size), &s.gas) != MemError::Ok) {
        s.status = EVMC_OUT_OF_GAS; return false;
    }
    const int64_t data_cost = static_cast<int64_t>(size) * GAS_LOGDATA;
    if (s.gas < data_cost) { s.status = EVMC_OUT_OF_GAS; return false; }
    s.gas -= data_cost;

    // topics[i] is the word just below (offset, size): sp+2 .. sp+1+n.
    evmc_bytes32 topics[4];
    for (unsigned i = 0; i < n; ++i)
        u256_to_be(s.stack[sp + 2 + i], topics[i].bytes);  // LE slot -> BE wire topic

    const uint8_t* data = size != 0 ? EVMMem::data(static_cast<size_t>(off)) : nullptr;
    s.host->emit_log(s.context, &s.evmcMsg->recipient, data, static_cast<size_t>(size),
                     topics, n);

    s.stackPointer += 2 + n;  // pop offset, size, and the n topics
    ++s.pc;
    return true;
}

bool op_log0(EvmState& s) { return log_impl(s, 0); }
bool op_log1(EvmState& s) { return log_impl(s, 1); }
bool op_log2(EvmState& s) { return log_impl(s, 2); }
bool op_log3(EvmState& s) { return log_impl(s, 3); }
bool op_log4(EvmState& s) { return log_impl(s, 4); }

}  // namespace


}  // namespace zevm

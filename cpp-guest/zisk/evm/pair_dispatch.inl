// pair_dispatch.inl — fused opcode pairs: an opcode and the one after it run
// as one step.
//
// The pairs are listed once (ZEG_PAIRS_LIST) and entered two ways, both from
// the top of the first opcode's generic handler (ZEG_TRY_FUSE):
//   - a row: PUSH1 reads the opcode after its immediate and jumps through its
//     own 256-entry table of handlers (`zeg_rows`), so its 13 partners cost
//     one indexed jump (8 instructions) whether one matches or none does;
//   - a peek: every other first opcode tests the next opcode against its one
//     to four partners, most frequent first (3 instructions per test).
// Every opcode without a fused partner keeps evmone's one-byte dispatch and
// pays nothing.
//
// Measured on ZisK (ziskemu cost, identical inputs, against develop):
//   - Nethermind's zkVM guest dispatches *every* opcode on the opcode pair, a
//     65,536-entry table. Here that dispatch alone, with no fused entry, cost
//     +3.8% on mainnet and +13% on Sepolia blocks: reading and indexing two
//     bytes on every dispatch costs more than the fusions give back on mainnet.
//   - Rows for every first opcode with a partner (PUSH2, ISZERO, EQ, LT, GT,
//     POP, SWAPn, ...) cost +0.8% on mainnet: a row miss costs more than a
//     one- or two-way peek, and the POP/SWAPn pairs (POP POP, SWAP1 POP, ...)
//     save too little. Only PUSH1, with many partners, gains from a row.
//   - This file as it stands: -0.56% cost on 31 mainnet blocks (every block
//     cheaper) and -39% on 27 Sepolia blocks, whose gas is half one gas-burning
//     loop (PUSH2 GAS LT PUSH1 JUMPI, PUSH1 ADD, PUSH2 POP, PUSH1 JUMP: four
//     fused steps per iteration instead of eleven dispatches).
//   - The misses are paid on the 200M benchmark blocks built from one
//     unpaired PUSH1 (PUSH1 0 PUSH0 PUSH0 CODECOPY, PUSH1 x GAS CALLDATACOPY):
//     +7 steps per PUSH1 there, 3-6% of those blocks. The costliest 200M
//     blocks do not move. Giving each unpaired opcode its own PUSH1 copy, so a
//     miss skips the second dispatch, cut the miss to +2 steps but cost more
//     on live blocks than it saved (see docs/perf-notes.md).
// The pairs were chosen from the opcode sequences executed on 31 mainnet and
// 300 Sepolia blocks (ZEG_PAIR_STATS, see pair_stats.inl).
//
// A fused handler is entered only at its first opcode; a jump onto the second
// still runs it alone, so JUMPDEST analysis is unchanged.
//
// Contract, the same as fused_dispatch.inl's, all or nothing: a fused handler
// either leaves position/gas/stack exactly as the generic handlers would, or
// touches nothing and continues at the first opcode's generic code (the label
// ZEG_G_<op>, past the row lookup or peeks), which then produces the exact
// error (stack underflow/overflow, out of gas, bad jump, an opcode undefined in
// this revision) at the exact gas. cpp-guest/test/fused_dispatch_difffuzz.cpp
// checks it against evmone's unpatched switch dispatch.
//
// Wiring (dispatch.inl): ZEG_TRY_FUSE runs the row lookup or the peeks (or
// fused_dispatch.inl's peek for JUMP and PUSH4) and then defines ZEG_G_<op>;
// ZEG_PAIR_INIT fills the rows on the run's first dispatch_cgoto call;
// ZEG_PAIR_TARGETS holds the fused handlers' labels.

#include <algorithm>
#include <climits>
#include <type_traits>
#include <utility>

// ---- static checks shared by the fused handlers -----------------------------

// The revision an opcode first exists in.
template <Opcode Op>
constexpr evmc_revision zeg_since()
{
    static_assert(instr::traits[Op].since.has_value(), "opcode never defined");
    return *instr::traits[Op].since;
}

// An opcode's base gas, which the fused handlers charge as a literal. Only
// valid when the price is the same in every revision the opcode exists in, so
// assert exactly that: a repricing EIP then breaks the build instead of
// silently mischarging (cf. zeg_gas_fixed in fused_dispatch.inl).
template <Opcode Op>
constexpr int64_t zeg_cost()
{
    constexpr auto since = zeg_since<Op>();
    constexpr int64_t c = instr::gas_costs[since][Op];
    static_assert(c >= 0);
    static_assert([] {
        for (int r = since; r <= EVMC_MAX_REVISION; ++r)
            if (instr::gas_costs[static_cast<evmc_revision>(r)][Op] != c)
                return false;
        return true;
    }(), "opcode price varies by revision: a fused handler can't charge it as a literal");
    return c;
}

// The stack a sequence of opcodes needs: the height it must start from to
// cover every opcode's inputs, and its highest point relative to the start
// over the opcodes that push (INT_MIN if none does).
template <Opcode... Ops>
constexpr std::pair<int, int> zeg_stack_bounds()
{
    constexpr size_t n = sizeof...(Ops);
    const int req[n] = {instr::traits[Ops].stack_height_required...};
    const int chg[n] = {instr::traits[Ops].stack_height_change...};
    int need = 0, peak = INT_MIN, cur = 0;
    for (size_t i = 0; i < n; ++i)
    {
        need = std::max(need, req[i] - cur);
        cur += chg[i];
        if (chg[i] > 0)
            peak = std::max(peak, cur);
    }
    return {need, peak};
}

// Run the sequence Ops... only if no opcode in it would fail its stack check:
// h (the height before) covers every opcode's inputs, and no push in the
// sequence, the transient ones included, takes the stack past 1024.
template <Opcode... Ops>
[[gnu::always_inline]] inline bool zeg_stack_ok(std::ptrdiff_t h) noexcept
{
    constexpr auto bounds = zeg_stack_bounds<Ops...>();
    if constexpr (bounds.first > 0)
        if (h < bounds.first)
            return false;
    if constexpr (bounds.second != INT_MIN)
        if (h + bounds.second > static_cast<std::ptrdiff_t>(StackSpace::limit))
            return false;
    return true;
}

// Every opcode of the sequence is defined in this revision. Only opcodes newer
// than Frontier can be undefined, and only they pay the test.
template <Opcode... Ops>
[[gnu::always_inline]] inline bool zeg_defined(const CostTable& cost_table) noexcept
{
    return ((zeg_since<Ops>() == EVMC_FRONTIER || cost_table[Ops] >= 0) && ...);
}

template <Opcode... Ops>
inline constexpr int64_t zeg_seq_cost = (zeg_cost<Ops>() + ...);

// An opcode whose generic handler is a plain stack transform with a constant
// price: what the generic fused handler can run.
template <Opcode Op>
constexpr bool zeg_plain()
{
    // The price itself is checked by zeg_cost: constant from the opcode's first
    // revision on (evmone's has_const_gas_cost also counts "undefined before
    // Constantinople" as a price change, so it rejects SHL and its kin).
    if constexpr (!instr::traits[Op].since.has_value())
        return false;
    else
        return std::is_convertible_v<decltype(instr::core::impl<Op>), void (*)(StackTop) noexcept>;
}

// ---- fused handlers ---------------------------------------------------------

// The arguments every fused handler receives (all live in dispatch_cgoto).
#define ZEG_FUSED_ARGS cost_table, stack_bottom, position, gas, state, code
#define ZEG_FUSED_PARAMS                                                                \
    const CostTable &cost_table, const uint256 *stack_bottom, Position &pos, int64_t &gas, \
        ExecutionState &state, const uint8_t *code

// A then B, two opcodes with no immediates.
template <Opcode A, Opcode B>
[[gnu::always_inline]] inline bool zeg_run_pair(ZEG_FUSED_PARAMS) noexcept
{
    const auto h = pos.stack_end - stack_bottom;

    // Conditional jumps "<test> PUSH2 <dst> JUMPI": fused_dispatch.inl's
    // zeg_try_fuse, entered from the row instead of a peek.
    if constexpr ((A == OP_ISZERO || A == OP_EQ) && B == OP_PUSH2)
    {
        (void)cost_table;
        return zeg_try_fuse<A>(stack_bottom, pos, gas, state, code);
    }
    // LT/GT PUSH1 <dst> JUMPI: compare and branch; neither the boolean nor the
    // target enters the stack.
    else if constexpr ((A == OP_LT || A == OP_GT) && B == OP_PUSH1)
    {
        (void)cost_table;
        const auto* p = pos.code_it;
        if (p[3] != OP_JUMPI || h < 2)
            return false;
        constexpr auto cost = zeg_seq_cost<A, OP_PUSH1, OP_JUMPI>;
        const auto& x = pos.stack_end[-1];
        const auto& y = pos.stack_end[-2];
        const bool taken = A == OP_LT ? x < y : y < x;
        if (taken)
        {
            if (!zeg_jump(pos, gas, state, code, p[2], cost + 1))
                return false;
        }
        else
        {
            if (!zeg_charge(gas, cost))
                return false;
            pos.code_it = p + 4;
        }
        pos.stack_end -= 2;
        return true;
    }
    // LT/GT/SLT/SGT PUSH2 <dst> JUMPI.
    else if constexpr ((A == OP_LT || A == OP_GT || A == OP_SLT || A == OP_SGT) && B == OP_PUSH2)
    {
        (void)cost_table;
        const auto* p = pos.code_it;
        if (p[4] != OP_JUMPI || h < 2)
            return false;
        constexpr auto cost = zeg_seq_cost<A, OP_PUSH2, OP_JUMPI>;
        const auto& x = pos.stack_end[-1];
        const auto& y = pos.stack_end[-2];
        bool taken;
        if constexpr (A == OP_LT)
            taken = x < y;
        else if constexpr (A == OP_GT)
            taken = y < x;
        else if constexpr (A == OP_SLT)
            taken = slt(x, y);
        else
            taken = slt(y, x);
        if (!zeg_branch(pos, gas, state, code, p + 1, taken, cost))
            return false;
        pos.stack_end -= 2;
        return true;
    }
    else
    {
        static_assert(zeg_plain<A>() && zeg_plain<B>(), "no fused handler for this pair");
        (void)state; (void)code;
        if (!zeg_stack_ok<A, B>(h) || !zeg_defined<A, B>(cost_table))
            return false;
        if (!zeg_charge(gas, zeg_seq_cost<A, B>))
            return false;
        instr::core::impl<A>(pos.stack_end);
        pos.stack_end += instr::traits[A].stack_height_change;
        instr::core::impl<B>(pos.stack_end);
        pos.stack_end += instr::traits[B].stack_height_change;
        pos.code_it += 2;
        return true;
    }
}

// PUSH<N> <imm> then B.
template <int N, Opcode B>
[[gnu::always_inline]] inline bool zeg_run_push(ZEG_FUSED_PARAMS) noexcept
{
    constexpr auto PUSH = static_cast<Opcode>(OP_PUSH1 + N - 1);
    const auto* p = pos.code_it;
    const uint64_t imm = N == 1 ? p[1] : (uint64_t{p[1]} << 8) | p[2];
    const auto h = pos.stack_end - stack_bottom;

    // PUSH2 JUMP/JUMPI: fused_dispatch.inl's zeg_try_fuse, from the row.
    if constexpr (N == 2 && (B == OP_JUMP || B == OP_JUMPI))
    {
        (void)cost_table; (void)imm; (void)h;
        return zeg_try_fuse<OP_PUSH2>(stack_bottom, pos, gas, state, code);
    }
    // PUSH2 y GAS LT: is the gas left (after GAS) below y. Neither y nor the
    // gas value enters the stack, only the boolean, and not even that when a
    // PUSH1 <dst> JUMPI follows.
    else if constexpr (N == 2 && B == OP_GAS)
    {
        (void)cost_table;
        if (p[4] != OP_LT || !zeg_stack_ok<PUSH, OP_GAS, OP_LT>(h))
            return false;
        const auto g = static_cast<uint64_t>(gas - zeg_cost<PUSH>() - zeg_cost<OP_GAS>());
        // ... PUSH1 <dst> JUMPI, a gas-bounded loop's exit test: branch on the
        // boolean directly.
        if (p[5] == OP_PUSH1 && p[7] == OP_JUMPI)
        {
            // The stack check above already covers the longer sequence.
            static_assert(zeg_stack_bounds<PUSH, OP_GAS, OP_LT, OP_PUSH1, OP_JUMPI>() ==
                          zeg_stack_bounds<PUSH, OP_GAS, OP_LT>());
            constexpr auto cost = zeg_seq_cost<PUSH, OP_GAS, OP_LT, OP_PUSH1, OP_JUMPI>;
            if (g < imm)
                return zeg_jump(pos, gas, state, code, p[6], cost + 1);
            if (!zeg_charge(gas, cost))
                return false;
            pos.code_it = p + 8;
            return true;
        }
        constexpr auto cost = zeg_seq_cost<PUSH, OP_GAS, OP_LT>;
        if (gas < cost)
            return false;
        gas -= cost;
        pos.stack_end[0] = uint256{g < imm};
        pos.stack_end += 1;
        pos.code_it = p + 5;
        return true;
    }
    // PUSH1 JUMP: the target never touches the stack, and the jump swallows
    // its landing JUMPDEST.
    else if constexpr (B == OP_JUMP)
    {
        (void)cost_table;
        return h < static_cast<std::ptrdiff_t>(StackSpace::limit) &&
               zeg_jump(pos, gas, state, code, imm, zeg_seq_cost<PUSH, OP_JUMP, OP_JUMPDEST>);
    }
    // PUSH1 JUMPI: branch on the top word.
    else if constexpr (B == OP_JUMPI)
    {
        (void)cost_table;
        if (h < 1 || h >= static_cast<std::ptrdiff_t>(StackSpace::limit))
            return false;
        constexpr auto cost = zeg_seq_cost<PUSH, OP_JUMPI>;
        const auto& c = pos.stack_end[-1];
        if ((c[0] | c[1] | c[2] | c[3]) != 0)
        {
            if (!zeg_jump(pos, gas, state, code, imm, cost + 1))
                return false;
        }
        else
        {
            if (!zeg_charge(gas, cost))
                return false;
            pos.code_it = p + N + 2;
        }
        pos.stack_end -= 1;
        return true;
    }
    // PUSH POP: nothing but the gas and the transient push's overflow check.
    else if constexpr (B == OP_POP)
    {
        (void)cost_table; (void)state; (void)code; (void)imm;
        if (h >= static_cast<std::ptrdiff_t>(StackSpace::limit) ||
            !zeg_charge(gas, zeg_seq_cost<PUSH, OP_POP>))
            return false;
        pos.code_it = p + N + 2;
        return true;
    }
    // PUSH1 x PUSH1 y.
    else if constexpr (B == OP_PUSH1)
    {
        (void)state; (void)code; (void)cost_table;
        if (!zeg_stack_ok<PUSH, OP_PUSH1>(h) || !zeg_charge(gas, zeg_seq_cost<PUSH, OP_PUSH1>))
            return false;
        pos.stack_end[0] = uint256{imm};
        pos.stack_end[1] = uint256{p[N + 2]};
        pos.stack_end += 2;
        pos.code_it = p + N + 3;
        return true;
    }
    else
    {
        static_assert(zeg_plain<B>(), "no fused handler for this PUSH follower");
        (void)state; (void)code;
        if (!zeg_stack_ok<PUSH, B>(h) || !zeg_defined<B>(cost_table) ||
            !zeg_charge(gas, zeg_seq_cost<PUSH, B>))
            return false;
        auto* top = pos.stack_end;
        // Arithmetic with a small immediate, word-wise; anything else pushes
        // the immediate and runs B's own handler on it.
        if constexpr (B == OP_ADD)
            top[-1] += imm;
        else if constexpr (B == OP_SUB)  // imm - top
            top[-1] = uint256{imm} - top[-1];
        else if constexpr (B == OP_AND)
            top[-1] = uint256{top[-1][0] & imm};
        else if constexpr (B == OP_SHL)
            top[-1] <<= imm;
        else if constexpr (B == OP_SHR)
            top[-1] >>= imm;
        else
        {
            top[0] = uint256{imm};
            instr::core::impl<B>(top + 1);
        }
        pos.stack_end = top + 1 + instr::traits[B].stack_height_change;
        pos.code_it = p + N + 2;
        return true;
    }
}

// ---- which pairs are fused ----------------------------------------------------
//
// ZEG_PAIRS_LIST(P): the fused pairs P(A, B); for PUSH1/PUSH2, B is the opcode
// after the immediate. Some pairs check a third opcode and fall back without
// it: <test> PUSH1/PUSH2 needs a JUMPI, PUSH2 GAS needs an LT. Within one first
// opcode, most frequent first: that is the order its peeks test them in.
// ZEG_PAIR_ROWS(R): the first opcodes that look their partner up in a row
// instead of peeking (see the top of this file). Tried and left out, as they
// cost more than they saved: POP POP, POP/SWAP1 JUMP, SWAP1 POP/SWAP2/DUP2,
// SWAP2 POP/SWAP1, SWAP3 POP/SWAP2, DUPn ADD, ADD SWAP1, DUP2 LT, and LT/GT/
// ISZERO/EQ ISZERO (the last -0.1% on mainnet as peeks), and SHL SUB (no
// change on live blocks; its peek made every other SHL 3 steps dearer, +5% on
// the 200M PUSH32 SHL benchmark).
#define ZEG_PAIRS_LIST(P)                                                                 \
    P(OP_PUSH1, OP_PUSH1) P(OP_PUSH1, OP_ADD) P(OP_PUSH1, OP_SHL) P(OP_PUSH1, OP_SHR)     \
    P(OP_PUSH1, OP_SUB) P(OP_PUSH1, OP_AND) P(OP_PUSH1, OP_DUP1) P(OP_PUSH1, OP_DUP2)     \
    P(OP_PUSH1, OP_DUP3) P(OP_PUSH1, OP_DUP4) P(OP_PUSH1, OP_SWAP1) P(OP_PUSH1, OP_JUMP)  \
    P(OP_PUSH1, OP_JUMPI)                                                                 \
    P(OP_PUSH2, OP_JUMPI) P(OP_PUSH2, OP_JUMP) P(OP_PUSH2, OP_POP) P(OP_PUSH2, OP_GAS)    \
    P(OP_ISZERO, OP_PUSH2) P(OP_EQ, OP_PUSH2)                                             \
    P(OP_LT, OP_PUSH2) P(OP_LT, OP_PUSH1) P(OP_GT, OP_PUSH2) P(OP_GT, OP_PUSH1)           \
    P(OP_SLT, OP_PUSH2) P(OP_SGT, OP_PUSH2)
#define ZEG_PAIR_ROWS(R) R(OP_PUSH1)

// ---- rows ---------------------------------------------------------------------

#define ZEG_ROW_OP(Op) Op,
inline constexpr Opcode zeg_row_ops[] = {ZEG_PAIR_ROWS(ZEG_ROW_OP)};
inline constexpr size_t zeg_nrows = std::size(zeg_row_ops);

// The row of an opcode, or -1.
template <Opcode Op>
inline constexpr int zeg_row_of = [] {
    for (size_t i = 0; i < zeg_nrows; ++i)
        if (zeg_row_ops[i] == Op)
            return static_cast<int>(i);
    return -1;
}();

// Where the opcode after Op is: past Op's immediate.
template <Opcode Op>
inline constexpr int zeg_next_at = 1 + instr::traits[Op].immediate_size;

// Full pointers: an aligned 8-byte load is the cheapest ZisK memory access (a
// 4-byte entry measured costlier).
inline void* zeg_rows[zeg_nrows][256];
inline bool zeg_rows_ready = false;

struct ZegSlot
{
    uint16_t row;
    uint8_t next;
};
// A pair whose first opcode peeks has no slot (row 0xffff, skipped).
#define ZEG_PAIR_SLOT(A, B)                                                          \
    ZegSlot{static_cast<uint16_t>(zeg_row_of<A> >= 0 ? zeg_row_of<A> : 0xffff),      \
        static_cast<uint8_t>(B)},
inline constexpr ZegSlot zeg_fused_slots[] = {ZEG_PAIRS_LIST(ZEG_PAIR_SLOT)};
inline constexpr size_t zeg_fused_count = std::size(zeg_fused_slots);

// Each row starts at its opcode's generic handler; the fused pairs then
// overwrite their entries.
[[gnu::noinline]] inline void zeg_rows_fill(
    void* const* generic, void* const* targets) noexcept
{
    for (size_t r = 0; r < zeg_nrows; ++r)
        for (auto& e : zeg_rows[r])
            e = generic[r];
    for (size_t i = 0; i < zeg_fused_count; ++i)
        if (zeg_fused_slots[i].row != 0xffff)
            zeg_rows[zeg_fused_slots[i].row][zeg_fused_slots[i].next] = targets[i];
    zeg_rows_ready = true;
}

// A fused pair: PUSH1/PUSH2 and the opcode after the immediate, or two opcodes.
template <Opcode A, Opcode B>
[[gnu::always_inline]] inline bool zeg_run(ZEG_FUSED_PARAMS) noexcept
{
    if constexpr (A == OP_PUSH1 || A == OP_PUSH2)
        return zeg_run_push<A - OP_PUSH1 + 1, B>(cost_table, stack_bottom, pos, gas, state, code);
    else
        return zeg_run_pair<A, B>(cost_table, stack_bottom, pos, gas, state, code);
}

// ---- the hooks ----------------------------------------------------------------

#define ZEG_DISPATCH() goto* cgoto_table[*position.code_it]

// At the top of OPCODE's generic handler: look the next opcode up in OPCODE's
// row, or test it against OPCODE's fused partners in list order, or run
// fused_dispatch.inl's peek; then the generic code, at ZEG_G_<OPCODE>, where a
// fused handler that bails out continues.
#define ZEG_PEEK(A, B)                                                                  \
    if constexpr (A == zeg_op)                                                          \
        if (position.code_it[zeg_next_at<A>] == B)                                      \
            goto ZEG_P_##A##_##B;
#define ZEG_TRY_FUSE(OPCODE)                                                            \
    if constexpr (zeg_row_of<OPCODE> >= 0)                                              \
        goto* zeg_rows[std::max(zeg_row_of<OPCODE>, 0)]                                 \
                      [position.code_it[zeg_next_at<OPCODE>]];                          \
    else                                                                                \
    {                                                                                   \
        [[maybe_unused]] constexpr Opcode zeg_op = OPCODE;                              \
        ZEG_PAIRS_LIST(ZEG_PEEK)                                                        \
        if constexpr (zeg_fusable<OPCODE>)                                              \
        {                                                                               \
            if (zeg_try_fuse<OPCODE>(stack_bottom, position, gas, state, code))         \
                ZEG_DISPATCH();                                                         \
        }                                                                               \
    }                                                                                   \
    ZEG_G_##OPCODE : __attribute__((unused));

#define ZEG_ROW_GENERIC(Op) &&ZEG_G_##Op,
#define ZEG_PAIR_ADDR(A, B) &&ZEG_P_##A##_##B,
#define ZEG_PAIR_INIT()                                                                 \
    do                                                                                  \
    {                                                                                   \
        if (!zeg_rows_ready) [[unlikely]]                                               \
        {                                                                               \
            static void* const zeg_generic[] = {ZEG_PAIR_ROWS(ZEG_ROW_GENERIC)};        \
            static void* const zeg_targets[] = {ZEG_PAIRS_LIST(ZEG_PAIR_ADDR)};         \
            zeg_rows_fill(zeg_generic, zeg_targets);                                    \
        }                                                                               \
    } while (0)

// The fused handlers; on a bail-out, the first opcode's generic code.
#define ZEG_PAIR_TARGET(A, B)                              \
    ZEG_P_##A##_##B : if (zeg_run<A, B>(ZEG_FUSED_ARGS))   \
        ZEG_DISPATCH();                                    \
    goto ZEG_G_##A;

#define ZEG_PAIR_TARGETS ZEG_PAIRS_LIST(ZEG_PAIR_TARGET)

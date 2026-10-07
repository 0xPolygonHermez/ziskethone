// fused_dispatch.inl — fused superinstructions for evmone's cgoto dispatch.
//
// A conditional or unconditional jump takes several opcodes back to back
// (PUSH2+JUMP, ISZERO+PUSH2+JUMPI, PUSH4+EQ+PUSH2+JUMPI, ...), each paying its
// own dispatch, gas check and 256-bit stack round-trip, and then a dispatch for
// the landing JUMPDEST. Running those sequences as one step saves 3.6% of a
// block's ZisK steps (2.4% of its cost), measured on 25 mainnet blocks on top
// of develop.
//
// Wiring: baseline_execution.cpp includes this file inside its anonymous
// namespace above dispatch_cgoto and calls ZEG_TRY_FUSE from its ON_OPCODE
// macro — that hook is all patch 06 contains. Active under ZEG_ZISK (guest) or
// ZEG_FUSE_TEST (the host differential fuzzer).
//
// Contract, all or nothing: zeg_try_fuse<Op>() either executes Op plus what
// follows — leaving position/gas/stack exactly as the generic handlers would —
// and returns true, or touches nothing at all and returns false so those
// handlers run instead. Stack underflow, stack overflow (including the
// transient overflow of an intermediate push), out of gas, a bad jump
// destination and opcodes too new for the revision all take that second path,
// so error codes and gas-at-halt stay bit-identical to the unfused
// interpreter. Peeking at code_it[k] is always safe: executable code is
// STOP-padded, and padding matches no pattern.
//
// Only jumps are fused, chosen from the most frequent opcode pairs and
// triples executed on mainnet blocks; each one cuts steps on all 25 blocks it
// was measured on. LT/GT/SLT/SGT + PUSH2 + JUMPI would save another 0.4% but
// are left out to keep the fused surface small. Fusions of PUSH1+{ADD,PUSH1,
// DUP2,SHL,SHR,SAR}, DUPn+MUL, POP+POP, SWAPn+{SWAPm,POP,PUSH1} and SGT+ISZERO
// cost more than they save: their generic handlers are cheap enough that the
// next-byte peek on every miss outweighs the fused path.

// The fused paths charge gas as literals, while the generic path reads the
// current revision's cost table. That is only equivalent for opcodes whose
// price is the same in every revision they exist in — so assert exactly that.
// A future repricing EIP then breaks the build instead of silently mischarging
// gas, which would change gas-at-halt and, through it, the block hash.
template <Opcode Op, int64_t Cost, evmc_revision Since = EVMC_FRONTIER>
constexpr bool zeg_gas_fixed()
{
    for (int r = Since; r <= EVMC_MAX_REVISION; ++r)
        if (instr::gas_costs[static_cast<evmc_revision>(r)][Op] != Cost)
            return false;
    return true;
}
static_assert(zeg_gas_fixed<OP_JUMP, 8>());
static_assert(zeg_gas_fixed<OP_JUMPI, 10>());
static_assert(zeg_gas_fixed<OP_JUMPDEST, 1>());   // the landing a taken jump swallows
static_assert(zeg_gas_fixed<OP_PUSH2, 3>());
static_assert(zeg_gas_fixed<OP_ISZERO, 3>());
static_assert(zeg_gas_fixed<OP_EQ, 3>());
static_assert(zeg_gas_fixed<OP_PUSH4, 3>());

// Entry opcodes with a fused fast path; every other opcode pays nothing.
template <Opcode Op>
constexpr bool zeg_fusable = Op == OP_JUMP || Op == OP_PUSH2 || Op == OP_PUSH4 ||
                             Op == OP_ISZERO || Op == OP_EQ;

// Attempt the fusion for OPCODE; on success re-dispatch directly. Expanded
// inside dispatch_cgoto's ON_OPCODE, where position/gas/... are in scope.
#define ZEG_TRY_FUSE(OPCODE)                                                    \
    if constexpr (zeg_fusable<OPCODE>)                                          \
    {                                                                           \
        if (zeg_try_fuse<OPCODE>(stack_bottom, position, gas, state, code))     \
            goto* cgoto_table[*position.code_it];                               \
    }

// Charge `cost` gas, or leave `gas` untouched and report failure so the
// caller falls back to the generic (and exactly-attributed) OOG path.
[[gnu::always_inline]] inline bool zeg_charge(int64_t& gas, int64_t cost) noexcept
{
    if (gas < cost)
        return false;
    gas -= cost;
    return true;
}

// Validated jump landing one past the JUMPDEST at `dst`, whose +1 gas is
// folded into `cost`. False (nothing mutated) on a bad destination or OOG.
[[gnu::always_inline]] inline bool zeg_jump(Position& pos, int64_t& gas, ExecutionState& state,
    const uint8_t* code, uint64_t dst, int64_t cost) noexcept
{
    if (!state.analysis.baseline->check_jumpdest(dst))
        return false;
    if (!zeg_charge(gas, cost))
        return false;
    pos.code_it = code + dst + 1;
    return true;
}

// The "PUSH2 <dst> JUMPI" every conditional fusion ends in, starting at `push2`:
// jump to its 16-bit immediate (+1 gas for the skipped JUMPDEST) when `taken`,
// else fall through past the JUMPI.
[[gnu::always_inline]] inline bool zeg_branch(Position& pos, int64_t& gas, ExecutionState& state,
    const uint8_t* code, const uint8_t* push2, bool taken, int64_t cost) noexcept
{
    if (taken)
        return zeg_jump(pos, gas, state, code, (uint64_t{push2[1]} << 8) | push2[2], cost + 1);
    if (!zeg_charge(gas, cost))
        return false;
    pos.code_it = push2 + 4;
    return true;
}

// The condition a conditional fusion branches on, from the words its test
// opcode consumes (`top` is one past the stack top).
template <Opcode Op>
[[gnu::always_inline]] inline bool zeg_test(const uint256* top, const uint8_t* p) noexcept
{
    // Word tests OR/XOR the four limbs by hand: intx's ==/!= compile to more
    // RISC-V instructions here, which shows up as steps.
    const auto& a = top[-1];
    if constexpr (Op == OP_PUSH2)  // bare JUMPI: jump if nonzero
        return (a[0] | a[1] | a[2] | a[3]) != 0;
    else if constexpr (Op == OP_ISZERO)
        return (a[0] | a[1] | a[2] | a[3]) == 0;
    else if constexpr (Op == OP_PUSH4)  // a == the 4-byte immediate (then EQ)
        return a[0] == ((uint64_t{p[1]} << 24) | (uint64_t{p[2]} << 16) |
                           (uint64_t{p[3]} << 8) | p[4]) &&
               (a[1] | a[2] | a[3]) == 0;
    else
    {
        const auto& b = top[-2];  // EQ
        return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])) == 0;
    }
}

template <Opcode Op>
[[gnu::always_inline]] inline bool zeg_try_fuse(const uint256* stack_bottom, Position& pos,
    int64_t& gas, ExecutionState& state, const uint8_t* code) noexcept
{
    const auto* p = pos.code_it;
    const auto height = pos.stack_end - stack_bottom;

    // JUMP lands on a validated JUMPDEST by definition: charge both (8+1) and
    // skip the JUMPDEST dispatch entirely.
    if constexpr (Op == OP_JUMP)
    {
        if (height < 1)
            return false;
        const auto& dst = pos.stack_end[-1];
        if ((dst[3] | dst[2] | dst[1]) != 0 || !zeg_jump(pos, gas, state, code, dst[0], 8 + 1))
            return false;
        --pos.stack_end;
        return true;
    }
    else
    {
        // PUSH2 + JUMP: the target never touches the stack (push then pop).
        if (Op == OP_PUSH2 && p[3] == OP_JUMP)
            return height < StackSpace::limit &&
                   zeg_jump(pos, gas, state, code, (uint64_t{p[1]} << 8) | p[2], 3 + 8 + 1);

        // Everything else is "<test> PUSH2 <dst> JUMPI": test the words the test
        // consumes directly, never materializing the boolean or the target.
        //   PUSH2 JUMPI                 bare JUMPI, consumes 1 word
        //   ISZERO PUSH2 JUMPI          consumes 1
        //   EQ PUSH2 JUMPI              consumes 2
        //   PUSH4 EQ PUSH2 JUMPI        Solidity's selector dispatch, consumes 1
        constexpr int at = Op == OP_PUSH2 ? 0 : Op == OP_PUSH4 ? 6 : 1;  // where the PUSH2 is
        constexpr int pops = (Op == OP_PUSH2 || Op == OP_ISZERO || Op == OP_PUSH4) ? 1 : 2;
        constexpr int64_t cost = (Op == OP_PUSH2 ? 3 : Op == OP_PUSH4 ? 3 + 3 + 3 : 3 + 3) + 10;
        // Peeking up to p[9] is safe: code is padded with 33 STOPs.
        if (p[at] != OP_PUSH2 || p[at + 3] != OP_JUMPI || (Op == OP_PUSH4 && p[5] != OP_EQ))
            return false;
        // A one-word test is followed by a push, which overflows a full stack:
        // that case stays generic. A two-word test frees a slot first.
        if (height < pops || (pops == 1 && height >= StackSpace::limit))
            return false;
        if (!zeg_branch(pos, gas, state, code, p + at, zeg_test<Op>(pos.stack_end, p), cost))
            return false;
        pos.stack_end -= pops;
        return true;
    }
}

// fused_dispatch.inl — fused superinstructions for evmone's cgoto dispatch.
//
// Opcodes that always run back to back (PUSH2+JUMP, ISZERO+PUSH2+JUMPI, ...)
// otherwise pay two dispatches, two gas checks and a 256-bit stack round-trip.
// Running each pattern as a single step is worth 2-9% of a block's ZisK steps.
//
// Wiring: baseline_execution.cpp includes this file inside its anonymous
// namespace above dispatch_cgoto and calls ZEG_TRY_FUSE from its ON_OPCODE
// macro — that hook is all patch 06 contains. Active under ZEG_ZISK (guest) or
// ZEG_FUSE_TEST (host unit tests, which multiply with intx instead of the
// arith256 precompile).
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
// Each fusion was ablated individually on mainnet blocks 25722395 and 25723923
// and cuts steps on both; drop one from zeg_fusable to re-measure it. Rejected
// as measured-negative: SWAPn+{SWAPm,POP,PUSH1} and SGT+ISZERO — their generic
// handlers are cheap enough that the next-byte peek on every miss costs more
// than the fused path saves.

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
static_assert(zeg_gas_fixed<OP_PUSH1, 3>());
static_assert(zeg_gas_fixed<OP_PUSH2, 3>());
static_assert(zeg_gas_fixed<OP_POP, 2>());
static_assert(zeg_gas_fixed<OP_ADD, 3>());
static_assert(zeg_gas_fixed<OP_MUL, 5>());
static_assert(zeg_gas_fixed<OP_DUP1, 3>());
static_assert(zeg_gas_fixed<OP_DUP2, 3>());
static_assert(zeg_gas_fixed<OP_ISZERO, 3>());
static_assert(zeg_gas_fixed<OP_EQ, 3>());
static_assert(zeg_gas_fixed<OP_SHL, 3, EVMC_CONSTANTINOPLE>());  // guarded by state.rev
static_assert(zeg_gas_fixed<OP_SHR, 3, EVMC_CONSTANTINOPLE>());
static_assert(zeg_gas_fixed<OP_SAR, 3, EVMC_CONSTANTINOPLE>());

// Entry opcodes with a fused fast path; every other opcode pays nothing.
template <Opcode Op>
constexpr bool zeg_fusable = Op == OP_JUMP || Op == OP_PUSH2 || Op == OP_PUSH1 ||
                             Op == OP_POP || Op == OP_ISZERO || Op == OP_EQ ||
                             Op == OP_DUP1 || Op == OP_DUP2;

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

// The "<test> PUSH2 JUMPI" tail shared by the conditional-jump triples: jump
// to the 16-bit immediate at p[2..3] (+1 gas for the skipped JUMPDEST) when
// `taken`, else fall through past the 5 fused bytes.
[[gnu::always_inline]] inline bool zeg_branch(Position& pos, int64_t& gas, ExecutionState& state,
    const uint8_t* code, const uint8_t* p, bool taken, int64_t cost) noexcept
{
    if (taken)
        return zeg_jump(pos, gas, state, code, (uint64_t{p[2]} << 8) | p[3], cost + 1);
    if (!zeg_charge(gas, cost))
        return false;
    pos.code_it = p + 5;
    return true;
}

// out = low 256 bits of out * b (the EVM MUL). ZisK: arith256 precompile,
// which reads its operands in place — b may alias out. Host test: intx.
[[gnu::always_inline]] inline void zeg_mul_into(uint256& out, const uint256& b) noexcept
{
#ifdef ZEG_ZISK
    uint64_t r[4];
    zeg_arith::mul_low(&out[0], &b[0], r);
    zeg_arith::store(out, r);
#else
    out = out * b;
#endif
}

template <Opcode Op>
[[gnu::always_inline]] inline bool zeg_try_fuse(const uint256* stack_bottom, Position& pos,
    int64_t& gas, [[maybe_unused]] ExecutionState& state,
    [[maybe_unused]] const uint8_t* code) noexcept
{
    const auto* p = pos.code_it;

    // JUMP lands on a validated JUMPDEST by definition: charge both (8+1) and
    // skip the JUMPDEST dispatch entirely.
    if constexpr (Op == OP_JUMP)
    {
        const auto height = pos.stack_end - stack_bottom;
        if (height < 1)
            return false;
        const auto& dst = pos.stack_end[-1];
        if ((dst[3] | dst[2] | dst[1]) != 0 || !zeg_jump(pos, gas, state, code, dst[0], 8 + 1))
            return false;
        --pos.stack_end;
        return true;
    }
    // PUSH2 + JUMP / JUMPI: the jump target never touches the uint256 stack;
    // taken jumps also skip the landing JUMPDEST.
    else if constexpr (Op == OP_PUSH2)
    {
        const auto height = pos.stack_end - stack_bottom;
        if (height >= StackSpace::limit)  // the PUSH2 itself would overflow
            return false;
        const uint64_t dst = (uint64_t{p[1]} << 8) | p[2];
        if (p[3] == OP_JUMP)  // push then pop: net stack change 0
            return zeg_jump(pos, gas, state, code, dst, 3 + 8 + 1);
        if (p[3] == OP_JUMPI)
        {
            if (height < 1)
                return false;
            const auto& cond = pos.stack_end[-1];
            if ((cond[0] | cond[1] | cond[2] | cond[3]) != 0)
            {
                if (!zeg_jump(pos, gas, state, code, dst, 3 + 10 + 1))
                    return false;
            }
            else
            {
                if (!zeg_charge(gas, 3 + 10))
                    return false;
                pos.code_it = p + 4;
            }
            --pos.stack_end;
            return true;
        }
        return false;
    }
    // PUSH1 + {ADD, PUSH1, DUP2, SHL, SHR, SAR}: keep the immediate in a
    // register instead of a stack round-trip.
    else if constexpr (Op == OP_PUSH1)
    {
        const auto height = pos.stack_end - stack_bottom;
        const uint64_t imm = p[1];
        switch (p[2])
        {
        case OP_ADD:
        {
            // The transient overflow matters: at height == limit the PUSH1
            // must fail even though the fused pair is stack-neutral.
            if (height < 1 || height >= StackSpace::limit || !zeg_charge(gas, 3 + 3))
                return false;
            auto& top = pos.stack_end[-1];
            const auto lo = top[0] + imm;
            if (lo < imm)  // carry out of the low word
            {
                if (++top[1] == 0 && ++top[2] == 0)
                    ++top[3];
            }
            top[0] = lo;
            pos.code_it = p + 3;
            return true;
        }
        case OP_PUSH1:
        {
            if (height + 2 > StackSpace::limit || !zeg_charge(gas, 3 + 3))
                return false;
            pos.stack_end[0] = imm;
            pos.stack_end[1] = uint64_t{p[3]};
            pos.stack_end += 2;
            pos.code_it = p + 4;
            return true;
        }
        case OP_DUP2:
        {
            if (height < 1 || height + 2 > StackSpace::limit || !zeg_charge(gas, 3 + 3))
                return false;
            const auto x = pos.stack_end[-1];  // the value DUP2 duplicates
            pos.stack_end[0] = imm;
            pos.stack_end[1] = x;
            pos.stack_end += 2;
            pos.code_it = p + 3;
            return true;
        }
        case OP_SHL:
        case OP_SHR:
        case OP_SAR:
        {
            // The pushed immediate is the shift amount (top of stack); the
            // value below it is shifted. imm is one byte, so always < 256.
            // Same transient-overflow rule as ADD.
            if (height < 1 || height >= StackSpace::limit ||
                state.rev < EVMC_CONSTANTINOPLE || !zeg_charge(gas, 3 + 3))
                return false;
            auto& v = pos.stack_end[-1];
            if (p[2] == OP_SHL)
                v = v << imm;
            else if (p[2] == OP_SHR)
                v = v >> imm;
            else
            {
                const bool negative = static_cast<int64_t>(v[3]) < 0;
                v = v >> imm;
                if (negative && imm != 0)
                    v |= ~uint256{} << (256 - imm);  // arithmetic sign fill
            }
            pos.code_it = p + 3;
            return true;
        }
        default:
            return false;
        }
    }
    // POP + POP.
    else if constexpr (Op == OP_POP)
    {
        if (p[1] != OP_POP || pos.stack_end - stack_bottom < 2 || !zeg_charge(gas, 2 + 2))
            return false;
        pos.stack_end -= 2;
        pos.code_it += 2;
        return true;
    }
    // ISZERO + PUSH2 + JUMPI: the ubiquitous "jump if zero" — test the top
    // word directly, never materializing the boolean or the jump target.
    else if constexpr (Op == OP_ISZERO)
    {
        const auto height = pos.stack_end - stack_bottom;
        if (p[1] != OP_PUSH2 || p[4] != OP_JUMPI || height < 1 || height >= StackSpace::limit)
            return false;
        const auto& v = pos.stack_end[-1];
        if (!zeg_branch(pos, gas, state, code, p, (v[0] | v[1] | v[2] | v[3]) == 0, 3 + 3 + 10))
            return false;
        --pos.stack_end;
        return true;
    }
    // EQ + PUSH2 + JUMPI: "jump if equal". EQ pops two and pushes one, so the
    // PUSH2 can never overflow and only underflow needs checking.
    else if constexpr (Op == OP_EQ)
    {
        if (p[1] != OP_PUSH2 || p[4] != OP_JUMPI || pos.stack_end - stack_bottom < 2)
            return false;
        const auto& a = pos.stack_end[-1];
        const auto& b = pos.stack_end[-2];
        const bool eq = ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])) == 0;
        if (!zeg_branch(pos, gas, state, code, p, eq, 3 + 3 + 10))
            return false;
        pos.stack_end -= 2;
        return true;
    }
    // DUPn + MUL: the arith256 precompile reads its operands from the stack
    // slots in place, so the duplicate never hits the stack. DUP1+MUL squares
    // the top; DUP2+MUL multiplies top by second, second preserved.
    else if constexpr (Op == OP_DUP1 || Op == OP_DUP2)
    {
        constexpr int64_t depth = Op == OP_DUP2 ? 2 : 1;
        const auto height = pos.stack_end - stack_bottom;
        if (p[1] != OP_MUL || height < depth || height >= StackSpace::limit ||
            !zeg_charge(gas, 3 + 5))
            return false;
        zeg_mul_into(pos.stack_end[-1], pos.stack_end[-depth]);
        pos.code_it = p + 2;
        return true;
    }
    else
        return false;
}

// fused_dispatch_difffuzz.cpp — differential fuzzer for the fused sequences
// (fused_dispatch.inl) and the opcode-pair dispatch (pair_dispatch.inl).
//
// Patch 06 hooks only evmone's cgoto dispatch, so its plain switch dispatch
// (set_option("cgoto", "no")) is an untouched reference in the same binary.
// Two parts:
//   - directed tests: every fused pattern as a straight line, on edge-case
//     operands, at stack heights 0..4 and 1022..1024, under every gas value
//     up to what the program costs, in revisions before and after the newer
//     opcodes (SHL/SHR, PUSH0);
//   - random programs biased toward the fused patterns and the conditions
//     that must make them bail (bad targets, tight gas, a full stack).
// Status, gas_left and output (1 KiB of memory, into which the programs spill
// stack words) must match.
//
// Build against an evmone compiled with -DZEG_FUSE_TEST (without it the fusions
// are #ifdef'd out and both sides run unfused), from a host build's patched
// evmone source (cpp-guest/build/_deps/evmone-src after a configure):
//   E=cpp-guest/build/_deps/evmone-src
//   cmake -S $E -B /tmp/ut -DEVMONE_TESTING=ON -DCMAKE_BUILD_TYPE=Release
//         -DCMAKE_CXX_FLAGS="-DZEG_FUSE_TEST -I$PWD/cpp-guest/zisk"
//   cmake --build /tmp/ut --target evmone -j$(nproc)
//   g++ -std=c++20 -O2 -o difffuzz cpp-guest/test/fused_dispatch_difffuzz.cpp
//       -I$E/include -I$E/evmc/include -I$E/lib -I<intx include dir>
//       -L/tmp/ut/lib -levmone -Wl,-rpath,/tmp/ut/lib
//   ./difffuzz 1000000 <seed>            # exit 0 == no divergence
//
// Before trusting a clean run, break one fusion (e.g. charge 3+3+9 instead of
// 3+3+10 for ISZERO+PUSH2+JUMPI, or compare with <= instead of <) and check
// that mismatches appear.

#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>

#include <cstdio>
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <random>
#include <utility>
#include <vector>

namespace
{
using Bytes = std::vector<uint8_t>;

enum : uint8_t
{
    OP_ADD = 0x01, OP_MUL = 0x02,
    OP_EQ = 0x14, OP_ISZERO = 0x15,
    OP_POP = 0x50, OP_MSTORE = 0x52,
    OP_JUMP = 0x56, OP_JUMPI = 0x57, OP_GAS = 0x5a, OP_JUMPDEST = 0x5b,
    OP_PUSH1 = 0x60, OP_PUSH2 = 0x61, OP_PUSH4 = 0x63, OP_PUSH32 = 0x7f,
    OP_DUP1 = 0x80, OP_SWAP1 = 0x90,
    OP_RETURN = 0xf3,
};

// Opcodes the opcode-pair table fuses, with their stack inputs and outputs:
// random runs of these produce every fused pair (pair_dispatch.inl's
// ZEG_PAIRS_LIST) next to unfused ones.
struct PairOp
{
    uint8_t op;
    int in, out;
};
constexpr PairOp kPairOps[] = {
    {0x01, 2, 1}, {0x03, 2, 1}, {0x10, 2, 1}, {0x11, 2, 1}, {0x12, 2, 1}, {0x13, 2, 1},
    {0x14, 2, 1}, {0x15, 1, 1}, {0x16, 2, 1}, {0x17, 2, 1}, {0x1b, 2, 1}, {0x1c, 2, 1},
    {0x1d, 2, 1}, {0x50, 1, 0}, {0x56, 1, 0}, {0x57, 2, 0}, {0x5a, 0, 1}, {0x5b, 0, 0},
    {0x5f, 0, 1}, {0x60, 0, 1}, {0x60, 0, 1}, {0x60, 0, 1}, {0x61, 0, 1}, {0x61, 0, 1},
    {0x80, 1, 2}, {0x81, 2, 3}, {0x82, 3, 4}, {0x83, 4, 5}, {0x90, 2, 2}, {0x91, 3, 3},
    {0x92, 4, 4},
};

// Emit a run that heavily favours the fused sequences. The generator tracks an
// approximate stack height and records real JUMPDEST offsets, so programs run
// deep instead of dying on the first POP or bad jump — while still emitting
// invalid targets, tight stacks and undefined opcodes often enough to exercise
// every bail-out path.
Bytes gen(std::mt19937_64& rng)
{
    std::uniform_int_distribution<int> pick(0, 99);
    std::uniform_int_distribution<int> byte(0, 255);
    Bytes c;
    std::vector<int> dests;          // offsets of emitted JUMPDESTs
    int sp = 0;                      // approximate stack height
    const int len = 20 + (int)(rng() % 200);

    auto need = [&](int n) {         // make sure n operands exist
        while (sp < n) { c.push_back(OP_PUSH1); c.push_back((uint8_t)byte(rng)); ++sp; }
    };
    auto bin = [&](uint8_t op) { need(2); c.push_back(op); --sp; };
    auto un  = [&](uint8_t op) { need(1); c.push_back(op); };

    if (pick(rng) < 10)              // sometimes park near the 1024 stack limit
    {
        const int n = 1015 + (int)(rng() % 15);
        for (int i = 0; i < n; ++i) { c.push_back(OP_PUSH1); c.push_back((uint8_t)byte(rng)); ++sp; }
    }

    // A jump target: mostly an emitted JUMPDEST, sometimes junk.
    auto target = [&]() -> int {
        return (!dests.empty() && pick(rng) < 75) ? dests[rng() % dests.size()]
                                                  : (int)(rng() % 300);
    };
    auto push2 = [&](int t) {
        c.push_back(OP_PUSH2); c.push_back((uint8_t)(t >> 8)); c.push_back((uint8_t)t); ++sp;
    };

    for (int i = 0; i < len; ++i)
    {
        const int r = pick(rng);
        if (r < 18) { c.push_back(OP_PUSH1); c.push_back((uint8_t)byte(rng)); ++sp; }
        else if (r < 26) { c.push_back(OP_JUMPDEST); dests.push_back((int)c.size() - 1); }
        else if (r < 34)
        {   // PUSH2 <target> JUMP/JUMPI
            push2(target());
            if (pick(rng) < 50) { need(2); c.push_back(OP_JUMPI); sp -= 2; }
            else { c.push_back(OP_JUMP); --sp; }
        }
        else if (r < 46)
        {   // <test> PUSH2 JUMPI, the shape Solidity emits for conditionals
            if (pick(rng) < 50) un(OP_ISZERO); else bin(OP_EQ);
            push2(target());
            need(2); c.push_back(OP_JUMPI); sp -= 2;
        }
        else if (r < 54)
        {   // PUSH4 <sel> EQ PUSH2 JUMPI, Solidity's selector dispatch; half the
            // time the compared word is that same selector, so the jump is taken
            const uint32_t sel = (uint32_t)rng();
            auto push4 = [&] {
                c.push_back(OP_PUSH4);
                for (int k = 3; k >= 0; --k) c.push_back((uint8_t)(sel >> (8 * k)));
                ++sp;
            };
            if (pick(rng) < 50) push4(); else need(1);
            push4();
            c.push_back(OP_EQ); --sp;
            push2(target());
            c.push_back(OP_JUMPI); sp -= 2;
        }
        else if (r < 58)
        {   // JUMP with its target already on the stack (not right after a PUSH2)
            const int t = target();
            if (t < 256) { c.push_back(OP_PUSH1); c.push_back((uint8_t)t); ++sp; }
            else { push2(t); c.push_back(OP_DUP1); ++sp; }   // leaves a copy behind
            c.push_back(OP_JUMP); --sp;
        }
        // Runs of opcodes from the set the opcode-pair table fuses (and their
        // neighbours), so every listed pair, and plenty of unlisted ones, meet
        // with random stack words, heights and gas.
        else if (r < 84)
        {
            const int run = 2 + (int)(rng() % 6);
            for (int k = 0; k < run; ++k)
            {
                const auto& o = kPairOps[rng() % std::size(kPairOps)];
                need(o.in);
                if (o.op == OP_PUSH1 || o.op == OP_PUSH2)
                {
                    c.push_back(o.op);
                    // A small immediate is often a jump target or a shift.
                    const int t = pick(rng) < 50 ? target() : byte(rng);
                    if (o.op == OP_PUSH2) c.push_back((uint8_t)(t >> 8));
                    c.push_back((uint8_t)t);
                }
                else
                    c.push_back(o.op);
                if (o.op == OP_JUMPDEST) dests.push_back((int)c.size() - 1);
                sp += o.out - o.in;
                if (sp < 0) sp = 0;
            }
        }
        // Observe the top word: DUP1 PUSH1 <slot> MSTORE. The returned memory
        // then shows any stack word a fused handler got wrong.
        else if (r < 90)
        {
            need(1);
            c.push_back(OP_DUP1);
            c.push_back(OP_PUSH1); c.push_back((uint8_t)(32 * (rng() % 32)));
            c.push_back(OP_MSTORE);
        }
        else if (r < 93) bin(OP_MUL);
        else if (r < 95) { c.push_back(OP_GAS); ++sp; }
        else if (r < 97) { c.push_back(OP_PUSH32); for (int k = 0; k < 32; ++k) c.push_back((uint8_t)byte(rng)); ++sp; }
        else { c.push_back((uint8_t)byte(rng)); }   // raw noise / undefined opcode
    }
    // Spill the stack's top words to memory, then return 1 KiB of it.
    for (int k = 0; k < std::min(sp, 16); ++k)
    {
        c.push_back(OP_PUSH2); c.push_back(0x02); c.push_back((uint8_t)(32 * k));
        c.push_back(OP_MSTORE);
    }
    c.push_back(OP_PUSH2); c.push_back(0x04); c.push_back(0x00);
    c.push_back(OP_PUSH1); c.push_back(0x00);
    c.push_back(OP_RETURN);
    return c;
}

struct Out
{
    evmc_status_code status;
    int64_t gas_left;
    Bytes output;
};

Out run(evmc::VM& vm, const Bytes& code, int64_t gas, evmc_revision rev)
{
    evmc::MockedHost host;
    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.gas = gas;
    msg.recipient = evmc_address{{0x01}};
    msg.sender = evmc_address{{0x02}};
    const auto r = vm.execute(host, rev, msg, code.data(), code.size());
    // Most generated programs halt without output, and EVMC then hands back
    // output_data == nullptr; build the empty Bytes explicitly.
    Bytes output;
    if (r.output_size != 0)
        output.assign(r.output_data, r.output_data + r.output_size);
    return {r.status_code, r.gas_left, std::move(output)};
}
}  // namespace

// Directed tests: every fused pattern as a straight line, on edge-case operands
// (equal words, 0, 1, 2^255, 2^256-1, a valid and an invalid jump target), at
// every stack height that matters (empty, short, 1023, 1024) and at every gas
// value up to what the program costs, so each bail-out boundary is crossed.
// Random programs rarely make two compared words equal or a GAS value meet
// the word it is compared with; these do.
struct Pattern
{
    std::vector<int> bytes;  // -1: a 1-byte jump target, -2: a 2-byte one
};

// Stack effect of the opcodes the directed patterns use.
int stack_delta(uint8_t op)
{
    switch (op)
    {
    case 0x01: case 0x03: case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x16:
    case 0x1b: case 0x1c: case 0x50: case 0x56: return -1;
    case 0x57: return -2;
    case 0x5a: case 0x5f: case 0x60: case 0x61: case 0x80: case 0x81: case 0x82: case 0x83:
        return 1;
    case 0x52: return -2;
    default: return 0;  // ISZERO, SWAPn, JUMPDEST, STOP, undefined
    }
}

// PUSH2 y GAS LT compares the gas left with y: sweep y across
// the exact gas value (equal, one below, one above), which random programs and
// the generic directed runs only reach when too little gas is left to observe it.
long directed_gas_lt(evmc::VM& fused, evmc::VM& plain)
{
    long mismatches = 0, runs = 0;
    for (int64_t gas = 60; gas < 4000; gas += 7)
    {
        for (int delta = -2; delta <= 2; ++delta)
        {
            // PUSH2 y GAS LT PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN; GAS sees
            // gas - 3 (PUSH2) - 2 (GAS).
            const int64_t y = gas - 5 + delta;
            const Bytes c = {OP_PUSH2, (uint8_t)(y >> 8), (uint8_t)y, OP_GAS, 0x10, OP_PUSH1, 0x00,
                OP_MSTORE, OP_PUSH1, 0x20, OP_PUSH1, 0x00, OP_RETURN};
            // ... and branching on it: PUSH1 15 JUMPI; fall through returns 0
            // bytes, the JUMPDEST at 15 returns 32.
            const int64_t y2 = gas - 5 + delta;
            const Bytes j = {OP_PUSH2, (uint8_t)(y2 >> 8), (uint8_t)y2, OP_GAS, 0x10, OP_PUSH1, 15,
                OP_JUMPI, OP_PUSH1, 0x00, OP_PUSH1, 0x00, OP_RETURN, 0xfe, 0xfe, OP_JUMPDEST,
                OP_PUSH1, 0x20, OP_PUSH1, 0x00, OP_RETURN};
            for (const auto* code : {&c, &j})
            {
                ++runs;
                const auto a = run(fused, *code, gas, EVMC_OSAKA);
                const auto b = run(plain, *code, gas, EVMC_OSAKA);
                if (a.status != b.status || a.gas_left != b.gas_left || a.output != b.output)
                {
                    ++mismatches;
                    std::printf("GAS-LT MISMATCH gas=%ld delta=%d\n", (long)gas, delta);
                    if (mismatches >= 5) return mismatches;
                }
            }
        }
    }
    std::printf("%ld gas-lt runs, %ld mismatches\n", runs, mismatches);
    return mismatches;
}

Bytes word(uint8_t fill, uint8_t last)
{
    Bytes w(32, fill);
    w[31] = last;
    return w;
}

long directed(evmc::VM& fused, evmc::VM& plain, std::mt19937_64& rng)
{
    const std::vector<Pattern> patterns = {
        {{0x5a, 0x10}},                                     // GAS LT
        {{0x10, 0x60, -1, 0x57}}, {{0x11, 0x60, -1, 0x57}},  // LT/GT PUSH1 d JUMPI
        {{0x10, 0x61, -2, 0x57}}, {{0x11, 0x61, -2, 0x57}},  // LT/GT/SLT/SGT PUSH2 d JUMPI
        {{0x12, 0x61, -2, 0x57}}, {{0x13, 0x61, -2, 0x57}},
        {{0x15, 0x61, -2, 0x57}}, {{0x14, 0x61, -2, 0x57}},  // ISZERO/EQ PUSH2 d JUMPI
        {{0x10, 0x60, 0x07, 0x01}}, {{0x10, 0x61, 0x00, 0x07, 0x01}},  // LT PUSH1/2, no JUMPI
        {{0x50, 0x56}}, {{0x90, 0x56}},                     // POP/SWAP1 JUMP
        {{0x60, -1, 0x56}}, {{0x60, -1, 0x57}},             // PUSH1 d JUMP/JUMPI
        {{0x61, -2, 0x56}}, {{0x61, -2, 0x57}},             // PUSH2 d JUMP/JUMPI
        {{0x61, 0x12, 0x34, 0x50}},                         // PUSH2 x POP
        {{0x60, 0xff, 0x60, 0x01}},                         // PUSH1 PUSH1
        {{0x60, 0x05, 0x01}}, {{0x60, 0x05, 0x03}}, {{0x60, 0xf0, 0x16}},  // PUSH1 x ADD/SUB/AND
        {{0x60, 0x08, 0x1b}}, {{0x60, 0xff, 0x1c}},         // PUSH1 x SHL/SHR
        {{0x60, 0x01, 0x80}}, {{0x60, 0x01, 0x81}}, {{0x60, 0x01, 0x82}}, {{0x60, 0x01, 0x83}},
        {{0x60, 0x01, 0x90}},                               // PUSH1 x DUP1-4/SWAP1
        {{0x50, 0x50}}, {{0x90, 0x50}}, {{0x91, 0x50}}, {{0x92, 0x50}},  // the generic pairs
        {{0x81, 0x01}}, {{0x82, 0x01}}, {{0x83, 0x01}}, {{0x01, 0x90}}, {{0x1b, 0x03}},
        {{0x91, 0x90}}, {{0x90, 0x91}}, {{0x92, 0x91}}, {{0x90, 0x81}}, {{0x81, 0x10}},
        {{0x10, 0x15}}, {{0x80, 0x82}},
        {{0x15, 0x15}}, {{0x14, 0x15}}, {{0x11, 0x15}}, {{0x12, 0x15}}, {{0x13, 0x15}},  // <cmp> ISZERO
        {{0x61, 0x00, 0x40, 0x5a, 0x10}},                   // PUSH2 y GAS LT
        {{0x61, 0x00, 0x40, 0x5a, 0x01}},                   // PUSH2 y GAS, no LT
        {{0x61, 0x00, 0x40, 0x5a, 0x10, 0x60, -1, 0x57}},   // PUSH2 y GAS LT PUSH1 d JUMPI
        {{0x61, 0x7f, 0xff, 0x5a, 0x10, 0x60, -1, 0x57}},   // same, taken
        {{0x61, 0x00, 0x40, 0x5a, 0x10, 0x60, 0x00, 0x01}}, // PUSH1 but no JUMPI
        // PUSH1 x then an opcode it has no fused handler with: the row sends
        // these to the generic PUSH1, which then dispatches that opcode.
        {{0x60, 0x07, 0x5f}}, {{0x60, 0x07, 0x5b}}, {{0x60, 0x07, 0x15}}, {{0x60, 0x07, 0x14}},
        {{0x60, 0x07, 0x61, 0x12, 0x34}}, {{0x60, 0x07, 0x52}}, {{0x60, 0x07, 0x0c}},
        {{0x60, 0x07, 0x00}},  // ... PUSH0/JUMPDEST/ISZERO/EQ/PUSH2/MSTORE/undefined/STOP
    };
    const evmc_revision revs[] = {EVMC_HOMESTEAD, EVMC_BYZANTIUM, EVMC_PARIS, EVMC_SHANGHAI,
        EVMC_OSAKA, EVMC_AMSTERDAM};
    long mismatches = 0, runs = 0;
    for (const auto& pat : patterns)
    {
        for (int variant = 0; variant < 48; ++variant)
        {
            // Layout: [PUSH1 L JUMP][JUMPDEST at jd0][spill + RETURN]
            //         [L: JUMPDEST][deep stack?][operands][pattern][spill + RETURN]
            //         [JUMPDEST at jd][spill + RETURN]
            // 1-byte jump targets land on jd0, near the start, which they can
            // reach even past a deep stack's 2 KiB of pushes; the rest on jd.
            const int nops = (int)(rng() % 5);
            // Deep variants start the pattern at a height of 1022 to 1024.
            const int deep = variant % 8 == 7 ? 1022 + (variant / 8) % 3 - nops : 0;
            // Spill exactly the words the pattern leaves (up to 4): one more
            // would underflow and hide the output.
            int net = 0;
            for (size_t i = 0; i < pat.bytes.size(); ++i)
            {
                const int b = pat.bytes[i];
                net += stack_delta((uint8_t)b);
                if (b == 0x60) ++i;          // skip PUSH1's immediate
                else if (b == 0x61) i += (pat.bytes[i + 1] == -2) ? 1 : 2;
            }
            // On a deep stack the spill's own pushes would overflow and hide
            // the outcome, so drop 3 words first: a fused handler that wrongly
            // let a push through at 1024 then succeeds where the generic fails.
            const int drop = deep > 0 ? 3 : 0;
            const int left = std::min(4, std::max(0, deep + nops + net - drop));
            Bytes c;
            auto spill = [&] {
                for (int k = 0; k < drop; ++k)
                    c.push_back(OP_POP);
                for (int k = 0; k < left; ++k)
                {
                    c.push_back(OP_PUSH2); c.push_back(0x01); c.push_back((uint8_t)(32 * k));
                    c.push_back(OP_MSTORE);
                }
                c.push_back(OP_PUSH2); c.push_back(0x02); c.push_back(0x00);
                c.push_back(OP_PUSH1); c.push_back(0x00);
                c.push_back(OP_RETURN);
            };
            c = {OP_PUSH1, 0, OP_JUMP};
            const size_t jd0 = c.size();
            c.push_back(OP_JUMPDEST);
            spill();
            c[1] = (uint8_t)c.size();
            c.push_back(OP_JUMPDEST);
            constexpr int64_t entry_gas = 3 + 8 + 1;
            for (int i = 0; i < deep; ++i) { c.push_back(OP_PUSH1); c.push_back((uint8_t)i); }
            std::vector<size_t> jd_fix;  // PUSH2 immediates that must hold jd
            for (int i = 0; i < nops; ++i)
            {
                c.push_back(OP_PUSH32);
                const auto k = rng() % 9;
                Bytes w = k == 0 ? word(0, 0) : k == 1 ? word(0, 1) : k == 2 ? word(0xff, 0xff)
                        : k == 3 ? word(0, 7) : k == 4 ? word(0, 0xf0) : word(0, 0);
                if (k == 5) w[0] = 0x80;                     // 2^255
                if (k == 6 || k == 7) jd_fix.push_back(c.size() + 30);  // jd, or jd + 1
                if (k == 8) for (auto& b : w) b = (uint8_t)rng();
                if (k == 7) w[31] = 1;  // marker: jd + 1 (not a JUMPDEST)
                c.insert(c.end(), w.begin(), w.end());
            }
            std::vector<size_t> d1, d2;
            for (int b : pat.bytes)
            {
                if (b == -1) { d1.push_back(c.size()); c.push_back(0); }
                else if (b == -2) { d2.push_back(c.size()); c.push_back(0); c.push_back(0); }
                else c.push_back((uint8_t)b);
            }
            spill();
            while (c.size() % 16 != 0) c.push_back(0xfe);  // INVALID filler
            const size_t jd = c.size();
            c.push_back(OP_JUMPDEST);
            spill();
            // Jump targets: mostly valid, sometimes one past (not a JUMPDEST).
            const size_t bad = rng() % 4 == 0 ? 1 : 0;
            for (auto at : d1) c[at] = (uint8_t)(jd0 + bad);
            for (auto at : d2) { c[at] = (uint8_t)((jd + bad) >> 8); c[at + 1] = (uint8_t)(jd + bad); }
            for (auto at : jd_fix)
            {
                const bool plus1 = c[at + 1] == 1;
                const size_t v = jd + (plus1 ? 1 : 0);
                c[at] = (uint8_t)(v >> 8); c[at + 1] = (uint8_t)v;
            }
            const auto rev = revs[rng() % std::size(revs)];
            // Every gas value from 0 up to the cost of a full run, past the
            // operands' pushes: every out-of-gas point inside the pattern.
            // A failing run (underflow, bad jump, ...) consumes all its gas, so
            // cap the sweep at the pattern's reach: 120 gas past the operands.
            const auto full = run(plain, c, 1'000'000, rev);
            const int64_t start = std::max<int64_t>(0, entry_gas + 3 * (deep + nops) - 2);
            const int64_t used = full.status == EVMC_SUCCESS ? 1'000'000 - full.gas_left
                                                             : start + 120;
            for (int64_t gas = start; gas <= used + 2; ++gas)
            {
                ++runs;
                const auto a = run(fused, c, gas, rev);
                const auto b = run(plain, c, gas, rev);
                if (a.status != b.status || a.gas_left != b.gas_left || a.output != b.output)
                {
                    ++mismatches;
                    std::printf("DIRECTED MISMATCH rev=%d gas=%ld fused=%d/%ld plain=%d/%ld code=",
                        (int)rev, (long)gas, (int)a.status, (long)a.gas_left, (int)b.status,
                        (long)b.gas_left);
                    for (auto x : c) std::printf("%02x", x);
                    std::printf("\n");
                    if (mismatches >= 5) return mismatches;
                }
            }
        }
    }
    std::printf("%ld directed runs, %ld mismatches\n", runs, mismatches);
    return mismatches;
}

int main(int argc, char** argv)
{
    const long iters = (argc > 1) ? std::atol(argv[1]) : 100000;
    const uint64_t seed = (argc > 2) ? std::stoull(argv[2]) : 12345;

    evmc::VM fused{evmc_create_evmone()};                 // dispatch_cgoto (patched)
    evmc::VM plain{evmc_create_evmone()};                 // plain switch dispatch
    // Without cgoto support both VMs would run the switch dispatch, the
    // fusions would never execute, and a clean run would prove nothing.
    if (plain.set_option("cgoto", "no") != EVMC_SET_OPTION_SUCCESS)
    {
        std::fprintf(stderr, "evmone built without cgoto dispatch; nothing to compare\n");
        return 2;
    }

    // Homestead and Byzantium predate SHL/SHR/SAR, Paris predates PUSH0: the
    // fused handlers must bail there and let the generic path fail.
    const evmc_revision revs[] = {EVMC_HOMESTEAD, EVMC_BYZANTIUM, EVMC_BERLIN, EVMC_LONDON,
        EVMC_PARIS, EVMC_SHANGHAI, EVMC_CANCUN, EVMC_PRAGUE, EVMC_OSAKA, EVMC_AMSTERDAM};
    const int nrevs = (int)(sizeof(revs) / sizeof(revs[0]));

    std::mt19937_64 rng(seed);
    long mismatches = directed(fused, plain, rng) + directed_gas_lt(fused, plain);
    for (long i = 0; i < iters; ++i)
    {
        const auto code = gen(rng);
        const auto rev = revs[rng() % nrevs];
        // Wide gas range: plenty of runs must die of OOG mid-sequence.
        const int64_t gas = (int64_t)(rng() % 60000) + 1;

        const auto a = run(fused, code, gas, rev);
        const auto b = run(plain, code, gas, rev);

        if (a.status != b.status || a.gas_left != b.gas_left || a.output != b.output)
        {
            ++mismatches;
            std::printf("MISMATCH iter=%ld rev=%d gas=%ld\n", i, (int)rev, (long)gas);
            std::printf("  fused: status=%d gas_left=%ld outlen=%zu\n",
                (int)a.status, (long)a.gas_left, a.output.size());
            std::printf("  plain: status=%d gas_left=%ld outlen=%zu\n",
                (int)b.status, (long)b.gas_left, b.output.size());
            std::printf("  code=");
            for (auto x : code) std::printf("%02x", x);
            std::printf("\n");
            if (mismatches >= 5) break;
        }
    }
    std::printf("%ld iterations, %ld mismatches\n", iters, mismatches);
    return mismatches == 0 ? 0 : 1;
}

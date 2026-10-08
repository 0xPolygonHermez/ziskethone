// fused_dispatch_difffuzz.cpp — differential fuzzer for the fused jump sequences.
//
// Patch 06 hooks only evmone's cgoto dispatch, so its plain switch dispatch
// (set_option("cgoto", "no")) is an untouched reference in the same binary.
// Random bytecode, biased toward the fused patterns and the conditions that must
// make them bail (bad targets, tight gas, a full stack), runs through both, and
// status / gas_left / output must match.
//
// Build against an evmone compiled with -DZEG_FUSE_TEST (without it the fusions
// are #ifdef'd out and both sides run unfused):
//   cmake -S <evmone-src> -B /tmp/ut -DEVMONE_TESTING=ON -DCMAKE_BUILD_TYPE=Release
//         -DCMAKE_CXX_FLAGS="-DZEG_FUSE_TEST -I$PWD/cpp-guest/zisk"
//   cmake --build /tmp/ut --target evmone -j$(nproc)
//   g++ -std=c++20 -O2 -o difffuzz cpp-guest/test/fused_dispatch_difffuzz.cpp
//       -I<evmone-src>/include -I<evmone-src>/evmc/include -I<evmone-src>/lib -I<intx>
//       $(find /tmp/ut -path "*evmone.dir*" -name "*.o") $(find /tmp/ut -name keccak.c.o)
//   ./difffuzz 1000000 <seed>            # exit 0 == no divergence
//
// Before trusting a clean run, break one fusion (e.g. charge 3+3+9 instead of
// 3+3+10 for ISZERO+PUSH2+JUMPI) and check that mismatches appear.

#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>

#include <cstdio>
#include <cstdint>
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
        // Generic opcodes between the patterns: none of them is fused.
        else if (r < 66) bin(OP_ADD);
        else if (r < 70) bin(OP_MUL);
        else if (r < 76) { need(1); c.push_back(OP_DUP1); ++sp; }
        else if (r < 82) { need(2); c.push_back(OP_SWAP1); }
        else if (r < 88) { need(1); c.push_back(OP_POP); --sp; }
        else if (r < 92) { need(2); c.push_back(OP_MSTORE); sp -= 2; }
        else if (r < 95) { c.push_back(OP_GAS); ++sp; }
        else if (r < 97) { c.push_back(OP_PUSH32); for (int k = 0; k < 32; ++k) c.push_back((uint8_t)byte(rng)); ++sp; }
        else { c.push_back((uint8_t)byte(rng)); }   // raw noise / undefined opcode
    }
    c.push_back(OP_PUSH1); c.push_back(0x20);
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

    const evmc_revision revs[] = {EVMC_HOMESTEAD, EVMC_BYZANTIUM, EVMC_BERLIN, EVMC_LONDON,
        EVMC_PARIS, EVMC_SHANGHAI, EVMC_CANCUN, EVMC_PRAGUE};
    const int nrevs = (int)(sizeof(revs) / sizeof(revs[0]));

    std::mt19937_64 rng(seed);
    long mismatches = 0;
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

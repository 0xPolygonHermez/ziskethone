// fused_dispatch_difffuzz.cpp — differential fuzzer for the fused superinstructions.
//
// Build (host, needs an evmone built with -DZEG_FUSE_TEST so the fusions are
// actually compiled in — a plain host evmone has them #ifdef'd out and the
// fuzzer would silently compare unfused against unfused):
//
//   cmake -S <evmone-src> -B /tmp/ut -DEVMONE_TESTING=ON -DCMAKE_BUILD_TYPE=Release \
//         -DCMAKE_CXX_FLAGS="-DZEG_FUSE_TEST -I$PWD/cpp-guest/zisk"
//   cmake --build /tmp/ut --target evmone -j$(nproc)
//   g++ -std=c++20 -O2 -o difffuzz cpp-guest/test/fused_dispatch_difffuzz.cpp \
//       -I<evmone-src>/include -I<evmone-src>/evmc/include -I<evmone-src>/lib -I<intx> \
//       $(find /tmp/ut -path "*evmone.dir*" -name "*.o") $(find /tmp/ut -name keccak.c.o)
//   ./difffuzz 150000 <seed>            # exit 0 == no divergence
//
// Sanity-check the harness before trusting a clean run: break one fusion (e.g.
// charge 2+1 instead of 2+2 for POP+POP) and confirm mismatches appear. A
// generator that dies on the first bad jump reports zero either way.
//
// Patch 06 hooks ONLY evmone's dispatch_cgoto, so the plain switch dispatch in
// the same binary is an untouched reference implementation. evmone exposes the
// choice at runtime (set_option("cgoto","no")), so we can run identical random
// bytecode through fused and unfused interpreters in one process, on identical
// host state, and compare status / gas_left / output byte-for-byte.
//
// The generator is biased toward the fused patterns and toward the conditions
// that must make them bail: invalid jump targets, tight gas, deep stacks.

#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace
{
using Bytes = std::vector<uint8_t>;

enum : uint8_t
{
    OP_STOP = 0x00, OP_ADD = 0x01, OP_MUL = 0x02, OP_SUB = 0x03,
    OP_LT = 0x10, OP_GT = 0x11, OP_SGT = 0x13, OP_EQ = 0x14, OP_ISZERO = 0x15,
    OP_AND = 0x16, OP_OR = 0x17, OP_SHL = 0x1b, OP_SHR = 0x1c, OP_SAR = 0x1d,
    OP_POP = 0x50, OP_MLOAD = 0x51, OP_MSTORE = 0x52,
    OP_JUMP = 0x56, OP_JUMPI = 0x57, OP_PC = 0x58, OP_GAS = 0x5a, OP_JUMPDEST = 0x5b,
    OP_PUSH1 = 0x60, OP_PUSH2 = 0x61, OP_PUSH32 = 0x7f,
    OP_DUP1 = 0x80, OP_DUP2 = 0x81, OP_DUP3 = 0x82,
    OP_SWAP1 = 0x90, OP_SWAP2 = 0x91,
    OP_RETURN = 0xf3, OP_REVERT = 0xfd,
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

    for (int i = 0; i < len; ++i)
    {
        const int r = pick(rng);
        if (r < 18) { c.push_back(OP_PUSH1); c.push_back((uint8_t)byte(rng)); ++sp; }
        else if (r < 24) { c.push_back(OP_JUMPDEST); dests.push_back((int)c.size() - 1); }
        else if (r < 32)
        {   // PUSH2 <target> JUMP/JUMPI — mostly a real JUMPDEST, sometimes junk
            int t;
            if (!dests.empty() && pick(rng) < 75) t = dests[rng() % dests.size()];
            else t = (int)(rng() % 300);
            c.push_back(OP_PUSH2); c.push_back((uint8_t)(t >> 8)); c.push_back((uint8_t)t);
            ++sp;
            if (pick(rng) < 50) { need(2); c.push_back(OP_JUMPI); sp -= 2; }
            else { c.push_back(OP_JUMP); --sp; }
        }
        else if (r < 40)
        {   // ISZERO/EQ + PUSH2 + JUMPI triples, the shape Solidity emits
            if (pick(rng) < 50) { un(OP_ISZERO); } else { bin(OP_EQ); }
            int t = (!dests.empty() && pick(rng) < 75) ? dests[rng() % dests.size()]
                                                      : (int)(rng() % 300);
            c.push_back(OP_PUSH2); c.push_back((uint8_t)(t >> 8)); c.push_back((uint8_t)t);
            need(2); c.push_back(OP_JUMPI); sp -= 2;
        }
        else if (r < 46) { need(2); c.push_back(OP_POP); c.push_back(OP_POP); sp -= 2; }
        else if (r < 52) { need(1); c.push_back(OP_DUP1); ++sp; c.push_back(OP_MUL); --sp; }
        else if (r < 58) { need(2); c.push_back(OP_DUP2); ++sp; c.push_back(OP_MUL); --sp; }
        else if (r < 64) { need(1); c.push_back(OP_PUSH1); c.push_back((uint8_t)byte(rng)); ++sp;
                           c.push_back(OP_ADD); --sp; }
        else if (r < 70) { need(1); c.push_back(OP_PUSH1); c.push_back((uint8_t)byte(rng)); ++sp;
                           const uint8_t sh[3]={OP_SHL,OP_SHR,OP_SAR};
                           c.push_back(sh[rng()%3]); --sp; }
        else if (r < 74) { need(1); c.push_back(OP_PUSH1); c.push_back((uint8_t)byte(rng)); ++sp;
                           c.push_back(OP_DUP2); ++sp; }
        else if (r < 78) bin(OP_ADD);
        else if (r < 82) bin(OP_MUL);
        else if (r < 85) bin(OP_SGT);
        else if (r < 88) { need(2); c.push_back(OP_SWAP1); }
        else if (r < 91) { need(1); c.push_back(OP_POP); --sp; }
        else if (r < 94) { need(2); c.push_back(OP_MSTORE); sp -= 2; }
        else if (r < 96) { c.push_back(OP_GAS); ++sp; }
        else if (r < 98) { c.push_back(OP_PUSH32); for (int k = 0; k < 32; ++k) c.push_back((uint8_t)byte(rng)); ++sp; }
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
    return {r.status_code, r.gas_left,
        Bytes(r.output_data, r.output_data + r.output_size)};
}
}  // namespace

int main(int argc, char** argv)
{
    const long iters = (argc > 1) ? std::atol(argv[1]) : 100000;
    const uint64_t seed = (argc > 2) ? std::stoull(argv[2]) : 12345;

    evmc::VM fused{evmc_create_evmone()};                 // dispatch_cgoto (patched)
    evmc::VM plain{evmc_create_evmone()};                 // plain switch dispatch
    plain.set_option("cgoto", "no");

    const evmc_revision revs[] = {
        EVMC_BERLIN, EVMC_LONDON, EVMC_PARIS, EVMC_SHANGHAI, EVMC_CANCUN, EVMC_PRAGUE,
        EVMC_HOMESTEAD, EVMC_BYZANTIUM,  // pre-Constantinople: shifts undefined
    };
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

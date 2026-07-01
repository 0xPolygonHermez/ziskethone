// test_square_long.cpp — host equivalence test: square_long(a) == mul_long(a,a).
//   c++ -std=c++20 -O2 -I.. test_square_long.cpp -o /tmp/t && /tmp/t
// square_long is a squaring specialization (diagonals + doubled cross terms); it
// must produce bit-for-bit the same integer as the full schoolbook self-multiply
// for every input, across many random multi-word values (top word forced nonzero
// to honour the no-leading-zero precondition), including the 2la-1 vs 2la return.

#include <cstdio>
#include <cstdint>
#include <random>
#include "../bignum.hpp"
using namespace zeg::bi;

static int g_fail = 0;

// A tiny SplitMix64 so the test is deterministic and self-contained.
static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd() {
    uint64_t z = (rng_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

int main() {
    int cases = 0, top_short = 0, top_full = 0;
    // Word counts 2..8; many random draws each.
    for (int la = 2; la <= 8; ++la) {
        for (int iter = 0; iter < 4000; ++iter) {
            uint64_t a[8 * 4];
            for (int i = 0; i < la * 4; ++i) a[i] = rnd();
            // Force the top word nonzero (precondition: no leading zero word).
            if (is_zero4(a + 4 * (la - 1))) a[4 * (la - 1)] = 1;
            // Occasionally make the very top limb small so the product's top word
            // can be zero (exercises the 2la-1 return branch).
            if ((iter & 7) == 0) { a[4*(la-1)+3] = 0; a[4*(la-1)+2] = 0; a[4*(la-1)+1] = 0; if(!a[4*(la-1)]) a[4*(la-1)]=1; }

            uint64_t s[2 * 8 * 4], m[2 * 8 * 4];
            int ls = square_long(a, la, s);
            int lm = mul_long(a, la, a, la, m);
            ++cases;
            if (ls == 2 * la - 1) ++top_short; else ++top_full;
            if (ls != lm) { std::printf("FAIL len la=%d iter=%d: sq=%d mul=%d\n", la, iter, ls, lm); ++g_fail; continue; }
            for (int i = 0; i < ls * 4; ++i)
                if (s[i] != m[i]) { std::printf("FAIL word la=%d iter=%d limb=%d\n", la, iter, i); ++g_fail; break; }
        }
    }
    std::printf("checked %d cases (top_short=%d, top_full=%d)\n", cases, top_short, top_full);
    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}

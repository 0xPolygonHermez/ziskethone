// Differential test for the shared-JUMPDEST-map admission check.
//
// Safety property (one-sided): whenever zeg_test_parses_like(t, v, n) returns
// true, evmone's own analysis of t and of v must agree on EVERY position.
// A false negative only costs a full scan; a false positive is a consensus bug.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

#include <evmone/baseline.hpp>

extern "C" bool zeg_test_parses_like(const uint8_t* tmpl, const uint8_t* variant,
                                     size_t size);

namespace {

// 8-byte aligned buffer, matching what the witness hands the guest.
std::vector<uint8_t>* aligned_buf(size_t n) {
    return new std::vector<uint8_t>(n);
}

bool maps_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    const auto aa = evmone::baseline::analyze({a, n});
    const auto ab = evmone::baseline::analyze({b, n});
    for (size_t i = 0; i < n; ++i)
        if (aa.check_jumpdest(i) != ab.check_jumpdest(i))
            return false;
    return true;
}

// Where the PUSH data lives in `code` (everything that is not an instruction
// start), and where the instruction starts are.
void classify(const uint8_t* code, size_t n, std::vector<size_t>& pushdata,
              std::vector<size_t>& boundaries) {
    size_t i = 0;
    while (i < n) {
        boundaries.push_back(i);
        const uint8_t op = code[i];
        const size_t adv = (op >= 0x60 && op <= 0x7f) ? size_t(op - 0x5e) : 1;
        for (size_t k = i + 1; k < i + adv && k < n; ++k)
            pushdata.push_back(k);
        i += adv;
    }
}

}  // namespace

int main() {
    std::mt19937_64 rng{0xC0FFEE};
    size_t cases = 0, accepted = 0, rejected = 0, violations = 0;
    size_t pushdata_accepted = 0, pushdata_cases = 0;

    for (int iter = 0; iter < 200000; ++iter) {
        const size_t n = 8 + (rng() % 2048);
        auto* tv = aligned_buf(n);
        uint8_t* t = tv->data();
        for (size_t i = 0; i < n; ++i) {
            // Bias towards realistic code: lots of PUSHes and JUMPDESTs.
            const uint64_t r = rng() % 100;
            t[i] = (r < 35) ? uint8_t(0x60 + rng() % 32)
                 : (r < 50) ? uint8_t(0x5b)
                            : uint8_t(rng() % 256);
        }

        std::vector<size_t> pushdata, boundaries;
        classify(t, n, pushdata, boundaries);

        auto* vv = aligned_buf(n);
        uint8_t* v = vv->data();
        std::memcpy(v, t, n);

        const int mode = iter % 5;
        if (mode == 0 && !pushdata.empty()) {
            // Immutable-style: perturb only PUSH data. Must be accepted.
            ++pushdata_cases;
            for (int k = 0; k < 1 + int(rng() % 40); ++k)
                v[pushdata[rng() % pushdata.size()]] = uint8_t(rng() % 256);
        } else if (mode == 1 && !boundaries.empty()) {
            // Perturb an instruction start — the dangerous direction.
            for (int k = 0; k < 1 + int(rng() % 4); ++k)
                v[boundaries[rng() % boundaries.size()]] = uint8_t(rng() % 256);
        } else if (mode == 2) {
            // Perturb anywhere.
            for (int k = 0; k < 1 + int(rng() % 20); ++k)
                v[rng() % n] = uint8_t(rng() % 256);
        } else if (mode == 4 && !boundaries.empty()) {
            // The dangerous mutation on purpose: turn one instruction start
            // into a PUSH, which shifts every boundary after it.
            v[boundaries[rng() % boundaries.size()]] = uint8_t(0x60 + rng() % 32);
        } else {
            // Unrelated code of the same length.
            for (size_t i = 0; i < n; ++i)
                v[i] = uint8_t(rng() % 256);
        }

        ++cases;
        const bool ok = zeg_test_parses_like(t, v, n);
        if (ok) {
            ++accepted;
            if (mode == 0) ++pushdata_accepted;
            if (!maps_equal(t, v, n)) {
                ++violations;
                std::fprintf(stderr, "VIOLATION iter=%d n=%zu mode=%d\n", iter, n, mode);
            }
        } else {
            ++rejected;
        }
        delete tv;
        delete vv;
    }

    std::printf("cases=%zu accepted=%zu rejected=%zu violations=%zu\n",
                cases, accepted, rejected, violations);
    std::printf("push-data-only mutations: %zu, of which accepted %zu\n",
                pushdata_cases, pushdata_accepted);
    return violations == 0 ? 0 : 1;
}

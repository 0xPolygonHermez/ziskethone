// Host test for zeg::ChunkedVector (zeg/chunked_vector.hpp): behaves like a
// vector, never moves an element, and — the point of it — never leaves a dead
// outgrown buffer behind, which a doubling std::vector would under the guest's
// never-freeing bump allocator (the OOM vectors in GLAMSTERDAM.md / HEAP_BUDGET.md).
//
// alloc_count.hpp counts total host heap bytes requested (not live), the host
// stand-in for the bump pointer, so "no dead buffers" is a measurable claim.

#include "alloc_count.hpp"

#include "zeg/chunked_vector.hpp"
#include "zeg/tx_arena.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <type_traits>
#include <vector>

namespace {

int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

long g_objs = 0;  // live Tracked objects (distinct from alloc_count::g_live bytes)

struct Tracked {
    long v;
    std::string pad;  // non-trivial, so moves/copies are observable
    explicit Tracked(long x) : v(x), pad(std::to_string(x)) { ++g_objs; }
    Tracked(const Tracked& o) : v(o.v), pad(o.pad) { ++g_objs; }
    Tracked(Tracked&& o) noexcept : v(o.v), pad(std::move(o.pad)) { ++g_objs; }
    Tracked& operator=(const Tracked&) = default;
    ~Tracked() { --g_objs; }
};

// The headline property: holding N elements requests about N element-slots of
// memory, not ~2N. A doubling std::vector copied into ever-bigger buffers
// requests ~2N and leaves ~N dead; ChunkedVector appends chunks (kFirst..kMax)
// and never recopies, so the total is N + at most the last chunk's slack.
template <std::size_t F, std::size_t M>
void no_dead_buffers() {
    const std::size_t N = 200000;
    std::size_t cv_bytes = 0;
    {
        zeg::ChunkedVector<long, F, M> cv;
        cv_bytes = alloc_count::bytes_of([&] {
            for (std::size_t i = 0; i < N; ++i) cv.emplace_back(static_cast<long>(i));
        });
        CHECK(cv.size() == N);
    }
    // Reference: a doubling vector's total requested bytes for the same N.
    std::size_t vec_bytes = 0;
    {
        std::vector<long> v;
        vec_bytes = alloc_count::bytes_of([&] {
            for (std::size_t i = 0; i < N; ++i) v.push_back(static_cast<long>(i));
        });
    }
    // Chunk caps sum to < N + kMax live slots; the pointer table doubles but is
    // 8 bytes per chunk. Bound generously at (N + 2*M) slots + 64 KiB table.
    const std::size_t live = N * sizeof(long);
    const std::size_t bound = (N + 2 * M) * sizeof(long) + 65536;
    std::printf("no_dead F=%zu M=%zu: chunked=%zu vec=%zu live=%zu bound=%zu\n",
                F, M, cv_bytes, vec_bytes, live, bound);
    CHECK(cv_bytes <= bound);
    // And strictly better than the doubling vector it replaces.
    CHECK(cv_bytes < vec_bytes);
}

// operator[] maps indices to the right element, and elements are contiguous
// within a chunk (the invariant locate() relies on).
template <std::size_t F, std::size_t M>
void locate() {
    zeg::ChunkedVector<long, F, M> v;
    const std::size_t N = 100000;
    for (std::size_t i = 0; i < N; ++i) v.emplace_back(static_cast<long>(i));
    for (std::size_t i = 0; i < N; ++i) CHECK(v[i] == static_cast<long>(i));
    std::size_t k = 0, start = 0;
    while (start < N) {
        const std::size_t cap = (k < 40 && (F << k) < M) ? (F << k) : M;
        for (std::size_t j = start + 1; j < start + cap && j < N; ++j)
            CHECK(&v[j] == &v[j - 1] + 1);
        start += cap;
        ++k;
    }
}

// Randomized push/pop/truncate/release/move against a std::vector oracle, with
// element-address stability and no leaks.
template <std::size_t F, std::size_t M, class Alloc>
void fuzz(unsigned seed) {
    std::mt19937_64 rng(seed);
    {
        zeg::ChunkedVector<Tracked, F, M, Alloc> cv;
        std::vector<long> ref;
        std::vector<const Tracked*> addr;
        for (int step = 0; step < 120000; ++step) {
            const unsigned op = rng() % 100;
            if (op < 60) {
                const long x = static_cast<long>(rng());
                Tracked& t = cv.emplace_back(x);
                ref.push_back(x);
                if (addr.size() < ref.size()) addr.push_back(&t);
                else addr[ref.size() - 1] = &t;  // reused slot after a pop
            } else if (op < 75) {
                if (!ref.empty()) { cv.pop_back(); ref.pop_back(); }
            } else if (op < 85) {
                const std::size_t n = ref.empty() ? 0 : rng() % (ref.size() + 1);
                cv.truncate(n);
                ref.resize(n);
            } else if (op < 86) {
                cv.release(); ref.clear(); addr.clear();
            } else if (op < 88) {
                zeg::ChunkedVector<Tracked, F, M, Alloc> tmp(std::move(cv));
                CHECK(cv.size() == 0);
                cv = std::move(tmp);
                CHECK(tmp.size() == 0);
            } else {
                CHECK(cv.size() == ref.size());
                if (!ref.empty()) CHECK(cv.back().v == ref.back());
                std::size_t i = 0;
                for (const auto& t : static_cast<const decltype(cv)&>(cv)) {
                    CHECK(t.v == ref[i]);
                    CHECK(&t == addr[i]);  // never moved
                    ++i;
                }
                CHECK(i == ref.size());
            }
            CHECK(g_objs == static_cast<long>(cv.size()));
        }
    }
    CHECK(g_objs == 0);
    std::printf("fuzz ok F=%zu M=%zu seed=%u\n", F, M, seed);
}

// Push/pop around chunk boundaries, checking back() and address at each step.
template <std::size_t F, std::size_t M>
void edges() {
    zeg::ChunkedVector<Tracked, F, M> cv;
    std::vector<long> ref;
    std::mt19937_64 rng(F * 131 + M);
    for (int round = 0; round < 1500; ++round) {
        const std::size_t target = rng() % 700;
        while (ref.size() < target) { const long x = static_cast<long>(rng()); cv.emplace_back(x); ref.push_back(x); }
        for (int s = 0; s < 40; ++s) {
            if (rng() % 2 && !ref.empty()) { cv.pop_back(); ref.pop_back(); }
            else { const long x = static_cast<long>(rng()); cv.emplace_back(x); ref.push_back(x); }
            CHECK(cv.size() == ref.size());
            if (!ref.empty()) {
                CHECK(cv.back().v == ref.back());
                CHECK(&cv.back() == &cv[ref.size() - 1]);
            }
        }
        if (rng() % 5 == 0) { const std::size_t n = ref.empty() ? 0 : rng() % (ref.size() + 1); cv.truncate(n); ref.resize(n); }
    }
    std::printf("edges ok F=%zu M=%zu\n", F, M);
}

// A TxReceipt-like aggregate moved by std::vector reallocation keeps its logs
// (the kFirst=1 receipt-logs case): the receipts vector reallocating must not
// disturb or leak any ChunkedVector it holds.
struct Rcpt {
    int a{0};
    std::array<uint8_t, 256> bloom{};
    zeg::ChunkedVector<Tracked, 1, 128> logs;
};
static_assert(std::is_nothrow_move_constructible_v<Rcpt>);
static_assert(!std::is_copy_constructible_v<Rcpt>);

void receipts() {
    std::vector<Rcpt> rs;
    std::vector<const Tracked*> first;
    for (int i = 0; i < 4000; ++i) {
        rs.emplace_back().a = i;
        for (int j = 0; j < i % 200; ++j) rs.back().logs.emplace_back(i * 1000 + j);
        first.push_back(rs.back().logs.empty() ? nullptr : &rs.back().logs[0]);
    }
    for (int i = 0; i < 4000; ++i) {
        const Rcpt& r = rs[i];
        CHECK(r.a == i);
        CHECK(r.logs.size() == static_cast<std::size_t>(i % 200));
        if (!r.logs.empty()) CHECK(&r.logs[0] == first[i]);
        int j = 0;
        for (const auto& l : r.logs) { CHECK(l.v == i * 1000 + j); ++j; }
    }
    rs.clear();
    CHECK(g_objs == 0);
    std::printf("receipts ok\n");
}

}  // namespace

int main() {
    no_dead_buffers<256, 4096>();
    no_dead_buffers<4, 128>();
    no_dead_buffers<1, 128>();
    no_dead_buffers<64, 1024>();

    locate<256, 4096>(); locate<4, 128>(); locate<64, 1024>();
    locate<16, 1024>(); locate<1, 128>(); locate<2, 8>(); locate<8, 8>();

    for (unsigned s = 1; s <= 2; ++s) {
        fuzz<256, 4096, std::allocator<Tracked>>(s);
        fuzz<4, 128, std::allocator<Tracked>>(s);
        fuzz<64, 1024, std::allocator<Tracked>>(s);
        fuzz<1, 128, std::allocator<Tracked>>(s);
        fuzz<256, 4096, zeg::TxArenaAllocator<Tracked>>(s);
        fuzz<1, 1, std::allocator<Tracked>>(s);
        fuzz<2, 8, std::allocator<Tracked>>(s);
    }
    edges<256, 4096>(); edges<4, 128>(); edges<64, 1024>();
    edges<1, 128>(); edges<1, 1>(); edges<2, 8>(); edges<8, 8>();
    receipts();

    std::printf(g_fail == 0 ? "ALL OK\n" : "%d FAILURES\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}

// Host test for zeg::Contracts staging (zeg/contracts.hpp, src/contracts.cpp):
// code a transaction deploys is copied into the tx arena, and settle_staged()
// keeps only the code whose owner still has its hash at the end of the
// transaction, dropping the rest. This is audit B in GLAMSTERDAM.md /
// HEAP_BUDGET.md: a frame that reverts (or an account that SELFDESTRUCTs) must
// not leave its deposited code on the never-freed heap, or EIP-8037's state-gas
// refund lets one transaction fill the heap.

#include "alloc_count.hpp"

#include "zeg/contracts.hpp"
#include "zeg/seeded_hash.hpp"
#include "zeg/stream.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include <evmone_precompiles/keccak.hpp>

namespace {

int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

evmc::bytes32 keccak(const std::vector<uint8_t>& code) {
    const auto d = ethash::keccak256(code.data(), code.size());
    evmc::bytes32 h;
    std::memcpy(h.bytes, d.bytes, 32);
    return h;
}

std::vector<uint8_t> code_of(uint8_t tag, std::size_t n) {
    std::vector<uint8_t> c(n);
    for (std::size_t i = 0; i < n; ++i) c[i] = static_cast<uint8_t>(tag + i);
    return c;
}

// An empty Contracts section: a u64 count of 0.
zeg::Contracts empty_contracts(const zeg::HashSeed& seed) {
    static uint8_t buf[8] = {0};
    const uint8_t* cursor = buf;
    zeg::set_stream_end(buf + sizeof(buf));
    return zeg::Contracts(cursor, seed);
}

void staging() {
    const uint8_t rs[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const zeg::HashSeed seed = zeg::HashSeed::derive(rs);

    const auto c1 = code_of(0x60, 64);    // owner 0 keeps it
    const auto c2 = code_of(0x90, 1024);  // owner 1 reverts / destroys it
    const auto h1 = keccak(c1);
    const auto h2 = keccak(c2);

    zeg::Contracts contracts = empty_contracts(seed);

    // Both deployed this transaction.
    contracts.insert(h1, c1.data(), c1.size(), /*owner=*/0);
    contracts.insert(h2, c2.data(), c2.size(), /*owner=*/1);
    CHECK(contracts.has(h1));
    CHECK(contracts.has(h2));
    // Idempotent per hash: a second deploy of the same code only records the owner.
    const auto before_size = contracts.size();
    contracts.insert(h1, c1.data(), c1.size(), /*owner=*/2);
    CHECK(contracts.size() == before_size);

    // End of transaction: owner 0 still has h1, owner 1 is empty (reverted),
    // owner 2 also still has h1.
    contracts.settle_staged([&](std::size_t owner) -> evmc::bytes32 {
        if (owner == 0 || owner == 2) return h1;
        return evmc::bytes32{};  // EMPTY: no code
    });

    // h1 survived and reads back correctly; its bytes now live on the heap, not
    // in the (about-to-be-reset) arena.
    CHECK(contracts.has(h1));
    CHECK(!contracts.has(h2));  // dropped
    const auto& kept = contracts.by_hash(h1);
    CHECK(kept.code_size == c1.size());
    CHECK(std::memcmp(kept.code, c1.data(), c1.size()) == 0);
    const uint8_t* kept_ptr = kept.code;

    // A later transaction re-deploys h1: already settled, so it is a no-op that
    // keeps the same heap bytes (no new copy), and still resolves.
    const std::size_t bytes = alloc_count::bytes_of([&] {
        contracts.insert(h1, c1.data(), c1.size(), /*owner=*/3);
        contracts.settle_staged([&](std::size_t) { return h1; });
    });
    CHECK(contracts.by_hash(h1).code == kept_ptr);  // unmoved
    CHECK(bytes == 0);                               // no re-copy of settled code
    std::printf("staging ok (kept 1, dropped 1)\n");
}

// Deploy-and-drop N distinct codes in a row (the audit-B loop). The copies live
// in the tx arena (freed here by the staged_codes_ swap, which stands in for the
// guest's arena reset), so what STAYS LIVE on the never-freed heap must be ~0 of
// the code — not the 2000*4096 = 8 MiB deployed. We measure net live bytes
// (alloc_count::g_live), the host analogue of the guest's bump pointer, not the
// total ever requested (which includes the transient copies and test churn).
void revert_loop() {
    const uint8_t rs[16] = {9,9,9,9,9,9,9,9,0,0,0,0,0,0,0,1};
    const zeg::HashSeed seed = zeg::HashSeed::derive(rs);
    zeg::Contracts contracts = empty_contracts(seed);
    const std::size_t live_before = alloc_count::g_live;
    for (std::size_t i = 0; i < 2000; ++i) {
        auto c = code_of(static_cast<uint8_t>(i), 4096);
        c[0] = static_cast<uint8_t>(i);
        c[1] = static_cast<uint8_t>(i >> 8);  // make each distinct
        contracts.insert(keccak(c), c.data(), c.size(), i);
        contracts.settle_staged([&](std::size_t) { return evmc::bytes32{}; });  // all reverted
    }
    const std::size_t kept = alloc_count::g_live - live_before;
    // Nothing kept: the live growth is only the contracts_ deque's forgotten
    // entries (64 B each, code null) plus index churn — nowhere near 8 MiB.
    std::printf("revert_loop live growth = %zu bytes for 2000 x 4096 B dropped\n", kept);
    CHECK(kept < 2000ull * 4096 / 4);
    for (std::size_t i = 0; i < 2000; ++i) {
        auto c = code_of(static_cast<uint8_t>(i), 4096);
        c[0] = static_cast<uint8_t>(i); c[1] = static_cast<uint8_t>(i >> 8);
        CHECK(!contracts.has(keccak(c)));
    }
    std::printf("revert_loop ok\n");
}

}  // namespace

int main() {
    staging();
    revert_loop();
    std::printf(g_fail == 0 ? "ALL OK\n" : "%d FAILURES\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}

// Host test for zeg/tx_arena.hpp in guest mode (ZEG_ZISK): the per-transaction
// arena and the LIFO FrameScratch that holds CREATE init-code analyses (audit D
// in GLAMSTERDAM.md / HEAP_BUDGET.md). We stand in a bump arena for the guest's
// runtime.cpp one. The key claims:
//   - FrameScratch hands the same bytes back after a rewind (frames nest LIFO),
//     so its footprint is the deepest live chain of frames, not their count;
//   - ChunkedVector in the arena survives release()+reset across transactions.
// Built with ASan under `make unit SANITIZE=1`, the arena reset poisons the
// whole region, so any read of pre-reset arena memory is caught.

#define ZEG_ZISK 1

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <variant>
#include <vector>

#if defined(__SANITIZE_ADDRESS__)
#  include <sanitizer/asan_interface.h>
#  define AC_POISON(p, n)   ASAN_POISON_MEMORY_REGION((p), (n))
#  define AC_UNPOISON(p, n) ASAN_UNPOISON_MEMORY_REGION((p), (n))
#else
#  define AC_POISON(p, n)   ((void)0)
#  define AC_UNPOISON(p, n) ((void)0)
#endif

namespace {

int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// ----- stand-in bump arena (the guest's runtime.cpp) ------------------------
constexpr std::size_t kArena = std::size_t{1} << 28;  // 256 MiB
uint8_t*    g_base = nullptr;
uint8_t*    g_top  = nullptr;
uint8_t*    g_low  = nullptr;
std::size_t g_arena_bytes = 0;  // total ever handed out (never-free stand-in)
std::size_t g_arena_calls = 0;

}  // namespace

extern "C" void* zeg_tx_arena_alloc(std::size_t size) noexcept {
    size = (size + 15) & ~std::size_t{15};
    if (static_cast<std::size_t>(g_low - g_base) < size) { std::puts("arena OOM"); std::abort(); }
    g_low -= size;
    g_arena_bytes += size;
    ++g_arena_calls;
    AC_UNPOISON(g_low, size);
    std::memset(g_low, 0xA5, size);  // arena memory is not zero once reused
    return g_low;
}
extern "C" void zeg_tx_arena_reset() noexcept {
    AC_POISON(g_base, kArena);
    g_low = g_top;
}

#include "zeg/chunked_vector.hpp"
#include "zeg/tx_arena.hpp"

namespace {

// FrameScratch: nesting frames each take a mark, allocate, and rewind on
// return. After a rewind the bytes are reused, so N sequential (non-nested)
// frames cost one frame's worth, not N.
void frame_scratch_reuse() {
    zeg::tx_arena_reset();
    zeg::FrameScratch fs;

    // Two sequential allocations with a rewind between reuse the same address.
    auto m0 = fs.mark();
    void* a = fs.alloc(1000);
    fs.rewind(m0);
    void* b = fs.alloc(1000);
    CHECK(a == b);

    // Nesting: inner allocation sits past the outer, and rewinding the inner
    // frees it for the next sibling.
    auto outer = fs.mark();
    void* o = fs.alloc(2000);
    auto inner = fs.mark();
    void* i1 = fs.alloc(500);
    CHECK(i1 != o);
    fs.rewind(inner);
    void* i2 = fs.alloc(500);
    CHECK(i1 == i2);          // sibling reuses the inner's bytes
    fs.rewind(outer);
    void* o2 = fs.alloc(10);
    CHECK(o2 == o);           // outer's bytes back after it returns
    (void)b;
    std::printf("frame_scratch_reuse ok\n");
}

// N sequential frames, each allocating a 128 KiB-analysis-sized block and
// rewinding, must not grow the arena without bound: the chunk is reused.
void frame_scratch_flat() {
    zeg::tx_arena_reset();
    const std::size_t before = g_arena_bytes;
    {
        zeg::FrameScratch fs;
        std::size_t after_first = 0;
        for (int frame = 0; frame < 5000; ++frame) {
            auto m = fs.mark();
            volatile uint8_t* p = static_cast<uint8_t*>(fs.alloc(147536));  // 128 KiB init analysis
            p[0] = 1; p[147535] = 2;
            fs.rewind(m);
            if (frame == 0) after_first = g_arena_bytes;
            // From the first frame on, no new arena bytes: the 1 MiB chunk holds it.
            if (frame > 0) CHECK(g_arena_bytes == after_first);
        }
        CHECK(g_arena_bytes - before <= (std::size_t{1} << 20) + 4096);  // one chunk
    }
    std::printf("frame_scratch_flat ok (%zu arena bytes for 5000 frames)\n",
                g_arena_bytes - before);
}

// A deep nest of frames each holding a 128 KiB analysis: the footprint is the
// chain depth, and all of it is returned when the frames unwind.
void frame_scratch_deep() {
    zeg::tx_arena_reset();
    zeg::FrameScratch fs;
    std::vector<zeg::FrameScratch::Mark> marks;
    const int depth = 64;
    for (int d = 0; d < depth; ++d) {
        marks.push_back(fs.mark());
        volatile uint8_t* p = static_cast<uint8_t*>(fs.alloc(147536));
        p[0] = static_cast<uint8_t>(d);
    }
    for (int d = depth - 1; d >= 0; --d) fs.rewind(marks[d]);
    // Everything is back; one more allocation reuses the base.
    auto m = fs.mark();
    void* base = fs.alloc(16);
    fs.rewind(m);
    void* again = fs.alloc(16);
    CHECK(base == again);
    std::printf("frame_scratch_deep ok\n");
}

// ChunkedVector in the arena across many transactions: release() then
// tx_arena_reset(), rebuild. Under ASan the reset poisons the region, so a
// stale pointer into a previous tx would be caught here.
struct A { std::size_t idx; uint64_t v; };
struct B { uint8_t addr[20]; uint8_t pos[32]; bool p; uint8_t old[32]; };
using Entry = std::variant<std::monostate, A, B>;

void arena_journal() {
    std::mt19937_64 rng(7);
    zeg::ChunkedVector<Entry, 256, 4096, zeg::TxArenaAllocator<Entry>> j;
    std::size_t total = 0;
    for (int tx = 0; tx < 300; ++tx) {
        j.release();
        zeg::tx_arena_reset();
        const std::size_t n = rng() % 15000;
        std::vector<std::size_t> cps;  // checkpoints to roll back to
        for (std::size_t i = 0; i < n; ++i) {
            const unsigned op = rng() % 10;
            if (op == 0) { cps.push_back(j.size()); j.emplace_back(std::monostate{}); }
            else if (op < 6) j.emplace_back(A{i, rng()});
            else if (op < 9) j.emplace_back(B{});
            else if (!cps.empty()) {
                const std::size_t cp = cps.back(); cps.pop_back();
                CHECK(std::holds_alternative<std::monostate>(j[cp]));
                while (j.size() > cp) { std::visit([](auto&) {}, j.back()); j.pop_back(); }
            }
        }
        total += n;
    }
    std::printf("arena_journal ok, %zu ops\n", total);
}

}  // namespace

int main() {
    g_base = static_cast<uint8_t*>(std::aligned_alloc(16, kArena));
    g_top = g_low = g_base + kArena;
    AC_POISON(g_base, kArena);

    frame_scratch_reuse();
    frame_scratch_flat();
    frame_scratch_deep();
    arena_journal();

    std::printf(g_fail == 0 ? "ALL OK\n" : "%d FAILURES\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}

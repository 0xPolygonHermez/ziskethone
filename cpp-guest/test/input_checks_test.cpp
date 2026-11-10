// Host test for small input-validation rules the 2026-11-10 audit asked for:
//
// - M1: an RLP header for a payload of 2^32 bytes or more needs 6..9 bytes; the
//   old 5-byte buffer overflowed (an ASan stack-buffer-overflow under SANITIZE=1).
// - P1: nonzero alignment padding is a second encoding of the same input and
//   must halt the guest.
// - W1: an ancestor field_count that no fork has must not hash as Prague.
//
// A guest rejection is zeg::fatal (an abort), so those cases run in a child.

#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "zeg/fork.hpp"
#include "zeg/rlp.hpp"
#include "zeg/stream.hpp"

namespace {

int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// Whether `f` halts the process (zeg::fatal aborts).
template <typename F>
bool halts(F f) {
    std::fflush(stdout);
    const pid_t pid = fork();
    if (pid == 0) {
        std::freopen("/dev/null", "w", stderr);
        f();
        std::_Exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return !(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void rlp_header_sizes() {
    using zeg::rlp::item_size;
    CHECK(item_size(55) == 56);
    CHECK(item_size(56) == 58);
    CHECK(item_size(65536) == 65540);
    CHECK(item_size((std::size_t{1} << 32) - 1) == (std::size_t{1} << 32) - 1 + 5);
    CHECK(item_size(std::size_t{1} << 32) == (std::size_t{1} << 32) + 6);
    CHECK(item_size(SIZE_MAX - 9) == SIZE_MAX);  // 1 + 8 header bytes
}

void alignment_padding() {
    alignas(8) uint8_t buf[16] = {1, 2, 3, 0, 0, 0, 0, 0, 9};
    zeg::set_stream_end(buf + sizeof(buf));
    // Three bytes consumed, five zero padding bytes: lands on the next word.
    const uint8_t* cursor = buf + 3;
    zeg::align_to_u64(cursor, 3);
    CHECK(cursor == buf + 8);

    CHECK(halts([&] {
        buf[5] = 1;  // a nonzero padding byte
        const uint8_t* c = buf + 3;
        zeg::align_to_u64(c, 3);
    }));
    zeg::set_stream_end(nullptr);
}

void ancestor_field_counts() {
    using zeg::ForkId;
    CHECK(zeg::fork_from_field_count(15) == ForkId::Berlin);
    CHECK(zeg::fork_from_field_count(21) == ForkId::Prague);
    CHECK(zeg::fork_from_field_count(23) == ForkId::Amsterdam);
    CHECK(zeg::fork_from_field_count(0) == ForkId::Prague);  // unset: old manifests
    CHECK(zeg::fork_from_field_count(22) == ForkId::Unknown);
    CHECK(zeg::fork_from_field_count(24) == ForkId::Unknown);
    // Each fork's count maps back to a fork with that count.
    for (ForkId f : {ForkId::Berlin, ForkId::London, ForkId::Shanghai, ForkId::Cancun,
                     ForkId::Prague, ForkId::Amsterdam}) {
        const auto n = zeg::fork_field_count(f);
        CHECK(zeg::fork_field_count(zeg::fork_from_field_count(n)) == n);
    }
}

}  // namespace

int main() {
    rlp_header_sizes();
    alignment_padding();
    ancestor_field_counts();
    if (g_fail == 0) std::printf("input_checks_test: OK\n");
    return g_fail == 0 ? 0 : 1;
}

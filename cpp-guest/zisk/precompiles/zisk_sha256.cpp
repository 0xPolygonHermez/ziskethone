/* zisk_sha256.cpp — Zisk syscall override for the SHA-256 compression step.
 *
 * Zisk's zkVM exposes a single CSR-based syscall (id 0x805) that runs one
 * full extend+compress round on a SHA-256 state given a 64-byte message
 * block. evmone's `sha256_run` already loops chunks of 64 bytes and feeds
 * them to a per-block compress; this file replaces that per-block step
 * with the syscall so the constraint-heavy bit-twiddling happens inside
 * Zisk's precompile rather than as ~75M rv64 ops in the guest.
 *
 * The contract matches the corresponding SP1 syscall pair:
 *   evmone hands us a u32×8 running state `h[]` plus a 64-byte chunk;
 *   we update `h[]` in place. Boilerplate (padding, block iteration) stays
 *   in evmone's portable code.
 *
 * Zisk's syscall ABI (from /tmp/zisk-v0.17.0/ziskos/entrypoint/src/syscalls/sha256f.rs):
 *
 *   struct SyscallSha256Params { state: &mut [u64; 4],
 *                                input: &    [u64; 8] }
 *   `csrs 0x805, <reg holding &params>`
 *
 * The Rust definition stores 8 SHA-256 u32 state words packed as 4 u64s
 * (little-endian within each u64) and the 64 message bytes raw in 8 u64s.
 * We pack/unpack at the boundary so the rest of evmone keeps its existing
 * `uint32_t state[8]` layout.
 *
 * Linked into z6m_guest.elf via prover/guest_zisk/CMakeLists.txt. evmone
 * picks it up because its sha256.cpp has a `#elif defined(ZISK)` branch
 * that calls `zisk_sha256_compress_block`.
 */
#include <cstdint>
#include <cstring>

namespace {

/* Mirror of Rust's SyscallSha256Params. */
struct ZiskSha256Params {
    std::uint64_t*       state; /* 4 × u64 = 8 × u32 SHA-256 state    */
    const std::uint64_t* input; /* 8 × u64 = 64 bytes of message block */
};

constexpr unsigned ZISK_SYSCALL_SHA256F = 0x805;

}  // namespace

/* One Zisk SHA-256 compression round.
 *
 * @param state  Running SHA-256 state, 8 u32 words. Updated in place.
 * @param block  Exactly 64 message bytes (the chunk evmone produced).
 */
extern "C" void zisk_sha256_compress_block(
    std::uint32_t       state[8],
    const std::uint8_t  block[64]) noexcept
{
    alignas(8) std::uint64_t state64[4];
    alignas(8) std::uint8_t  block64[64];

    /* Pack u32×8 → u64×4. On little-endian RISC-V (lp64), the two
     * consecutive u32 words land in the low and high halves of one u64. */
    for (unsigned i = 0; i < 4; ++i) {
        state64[i] = (static_cast<std::uint64_t>(state[2 * i + 1]) << 32) |
                      static_cast<std::uint64_t>(state[2 * i]);
    }

    /* Copy the chunk bytes into an 8-byte-aligned buffer so the syscall's
     * required alignment is honoured even if evmone hands us a misaligned
     * `chunk[]` (it's a stack array of unknown alignment). */
    std::memcpy(block64, block, 64);

    ZiskSha256Params params{
        state64,
        reinterpret_cast<const std::uint64_t*>(block64),
    };

    /* csrs <csr_addr>, <reg> — CSR-based syscall convention.
     * Zisk intercepts the write to CSR 0x805 and runs the precompile. */
    asm volatile("csrs %1, %0"
                 :
                 : "r"(&params), "i"(ZISK_SYSCALL_SHA256F)
                 : "memory");

    /* Unpack u64×4 → u32×8. */
    for (unsigned i = 0; i < 4; ++i) {
        state[2 * i]     = static_cast<std::uint32_t>(state64[i] & 0xFFFFFFFFu);
        state[2 * i + 1] = static_cast<std::uint32_t>(state64[i] >> 32);
    }
}

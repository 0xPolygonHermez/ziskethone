// keccak_zisk.cpp — accelerated Keccak-256 for the ZisK self-contained build.
//
// Drop-in replacement for evmone's evmone_precompiles/keccak.c. It provides the
// single public symbol the whole guest funnels through:
//
//   union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size)
//
// Every Keccak in the guest bottoms out here — zeg::keccak256_bytes32
// (zeg/keccak.hpp), the direct ethash::keccak256 in contracts.cpp, and the EVM
// KECCAK256 opcode inside evmone. Swapping this one symbol accelerates them all.
//
// The sponge construction is evmone's, unchanged; only the Keccak-f[1600]
// permutation is delegated to the ZisK precompile (CSR 0x800, `csrs`), which
// operates in place on a 25-element u64 state — exactly the layout evmone's
// sponge already builds. Limb/byte order matches: the state is native u64 and
// the absorb/squeeze are little-endian, which is identity on little-endian
// RISC-V, so the digest bytes are bit-for-bit identical to the software path.
//
// This mirrors crypto_sw.cpp (which supplies secp256k1 for the freestanding
// build); it is compiled only into the ZisK target (see CMakeLists.txt).

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <evmone_precompiles/keccak.h>  // union ethash_hash256, signature

#include "zeg/keccakf_cache.hpp"  // memo for repeated permutations, looked up by the executor
#include "zeg/zisk_dma.hpp"  // zisk_xmemcpy / zisk_xmemset (CSR 0x813 / 0x816)

// The whole sponge below treats a run of message bytes and a run of 64-bit
// lanes as the same thing: the first block is absorbed with a raw DMA copy, the
// per-lane absorb reads 8 bytes as a u64, the padding word is built byte by byte
// and XORed as a u64, and the digest is squeezed with another raw copy. Every
// one of those is the identity ONLY on a little-endian target. Ported to a
// big-endian one they would each need a byteswap and the hashes would silently
// come out wrong, so state the assumption once, here, and let the build fail
// instead.
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
              "keccak_zisk: absorb/squeeze reinterpret bytes as u64 lanes, which is only "
              "the identity on a little-endian target");

namespace {

// Every permutation goes through the memo rather than straight to the precompile: it is the
// Keccak-f the guest runs, with an executor-side lookup for states already permuted folded
// in. See zeg/keccakf_cache.hpp — in particular why believing the index it is handed is
// sound.
using zeg::keccakf_cache::zisk_keccakf;

// A u64 that promises nothing about alignment and is allowed to alias other
// types — the two things a message pointer violates. `aligned(1)` stops the
// compiler from assuming `p` is 8-byte aligned (it never is, message bytes land
// wherever the witness put them) and `may_alias` exempts the read from strict
// aliasing, which reading a uint8_t buffer through a uint64_t* otherwise breaks.
// With both, a plain dereference is well defined and GCC still picks the best
// load the target allows: one `ld` here, byte loads on a machine where unaligned
// access traps. A bare reinterpret_cast to uint64_t* would emit the same `ld`
// but promise an alignment that does not hold.
using unaligned_u64 [[gnu::aligned(1), gnu::may_alias]] = uint64_t;

// Read the 8 bytes at `p` as one lane. Not a copy and not a byteswap: a single
// `ld`. The byte order it produces is the target's, which the static_assert
// above pins to the one Keccak wants.
inline uint64_t load_lane(const uint8_t* p) {
    return *reinterpret_cast<const unaligned_u64*>(p);
}

// Keccak sponge for a 256-bit digest (rate r = 1600 - 2*256 = 1088 bits =
// 136 bytes). Pad10*1 with the Keccak domain byte 0x01 and the 0x80 terminator.
// Identical to evmone's static keccak(out, 256, …), with zisk_keccakf in
// place of the software permutation.
void keccak256_compute(uint64_t* out, const uint8_t* data, size_t size) {
    constexpr size_t word_size = sizeof(uint64_t);   // 8
    constexpr size_t hash_size = 256 / 8;            // 32
    constexpr size_t block_size = (1600 - 256 * 2) / 8;  // 136

    uint64_t state[25];
    constexpr size_t rate_words = block_size / word_size;      // 17 absorbed
    constexpr size_t cap_bytes  = sizeof(state) - block_size;  // 64 of capacity

    if (size >= block_size) {
        // First block: XOR against a zeroed state is just a copy, so absorb it
        // with one DMA op instead of zeroing 17 words and XORing them back in.
        // The capacity (the 8 words the rate never touches) still has to be
        // zeroed — the permutation reads the whole state, so leaving it
        // uninitialized silently changes the digest.
        zeg::zisk::zisk_xmemcpy<block_size>(state, data);
        zeg::zisk::zisk_xmemset<cap_bytes>(state + rate_words);
        data += block_size;
        zisk_keccakf(state);
        size -= block_size;
    } else {
        zeg::zisk::zisk_xmemset<sizeof(state)>(state);
    }

    while (size >= block_size) {
        for (size_t i = 0; i < block_size / word_size; ++i) {
            state[i] ^= load_lane(data);
            data += word_size;
        }
        zisk_keccakf(state);
        size -= block_size;
    }

    // Absorb the remaining full words, then the trailing partial word.
    uint64_t* state_iter = state;
    while (size >= word_size) {
        *state_iter ^= load_lane(data);
        ++state_iter;
        data += word_size;
        size -= word_size;
    }

    uint64_t last_word = 0;
    uint8_t* last_word_iter = reinterpret_cast<uint8_t*>(&last_word);
    // The tail is `size` bytes, 0..7 of them — a run-time count, so the register
    // form. A fixed-size copy here would write past `last_word`, which is a
    // single u64 on the stack.
    if (size > 0) {
        zeg::zisk::zisk_memcpy(last_word_iter, data, size);
        last_word_iter += size;
    }
    *last_word_iter = 0x01;            // Keccak (not SHA3) domain padding.
    *state_iter ^= last_word;          // little-endian target: store as-is.

    state[block_size / word_size - 1] ^= 0x8000000000000000ULL;  // 10*1 terminator.

    zisk_keccakf(state);

    // little-endian target: squeeze as-is.
    zeg::zisk::zisk_xmemcpy<hash_size>(out, state);
}

} // namespace

extern "C" union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size) noexcept {
    union ethash_hash256 hash;
    // No memo at this level any more. Remembering whole preimages was worth it only while
    // the permutation-level memo had to pay for its own lookups; now that the executor does
    // them, every repeat a message-keyed table could find is already a run of permutation
    // hits inside the sponge — and so are the repeats it could not see, the ones two
    // different messages share through a common 136-byte-aligned prefix.
    keccak256_compute(hash.word64s, data, size);
    return hash;
}

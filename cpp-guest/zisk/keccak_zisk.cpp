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

namespace {

// ZisK Keccak-f[1600] precompile. CSR 0x800 takes a pointer (in a register) to
// the 25-word state and permutes it in place. Matches the ziskos_syscall! macro
// (`csrs {port}, {value}`) and hello-zisk-c/zisk_cpp_howto.md §8.7.
inline void syscall_keccakf(uint64_t* state /* &state[25] */) {
    register unsigned long a0 asm("a0") = reinterpret_cast<unsigned long>(state);
    asm volatile("csrs 0x800, %0" : : "r"(a0) : "memory");
}

// Load 64 bits little-endian from a possibly-unaligned byte pointer.
inline uint64_t load_le(const uint8_t* p) {
    uint64_t w;
    std::memcpy(&w, p, sizeof(w));
    return w;  // little-endian target: bytes already in native order.
}

// Keccak sponge for a 256-bit digest (rate r = 1600 - 2*256 = 1088 bits =
// 136 bytes). Pad10*1 with the Keccak domain byte 0x01 and the 0x80 terminator.
// Identical to evmone's static keccak(out, 256, …), with syscall_keccakf in
// place of the software permutation.
void keccak256(uint64_t* out, const uint8_t* data, size_t size) {
    constexpr size_t word_size = sizeof(uint64_t);   // 8
    constexpr size_t hash_size = 256 / 8;            // 32
    constexpr size_t block_size = (1600 - 256 * 2) / 8;  // 136

    uint64_t state[25] = {0};

    while (size >= block_size) {
        for (size_t i = 0; i < block_size / word_size; ++i) {
            state[i] ^= load_le(data);
            data += word_size;
        }
        syscall_keccakf(state);
        size -= block_size;
    }

    // Absorb the remaining full words, then the trailing partial word.
    uint64_t* state_iter = state;
    while (size >= word_size) {
        *state_iter ^= load_le(data);
        ++state_iter;
        data += word_size;
        size -= word_size;
    }

    uint64_t last_word = 0;
    uint8_t* last_word_iter = reinterpret_cast<uint8_t*>(&last_word);
    while (size > 0) {
        *last_word_iter = *data;
        ++last_word_iter;
        ++data;
        --size;
    }
    *last_word_iter = 0x01;            // Keccak (not SHA3) domain padding.
    *state_iter ^= last_word;          // little-endian target: store as-is.

    state[block_size / word_size - 1] ^= 0x8000000000000000ULL;  // 10*1 terminator.

    syscall_keccakf(state);

    for (size_t i = 0; i < hash_size / word_size; ++i)
        out[i] = state[i];            // little-endian target: squeeze as-is.
}

} // namespace

#ifdef ZKVM_KECCAK
#include "zkvm_accelerators.h"
#endif

extern "C" union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size) noexcept {
    union ethash_hash256 hash;
#ifdef ZKVM_KECCAK
    // EF standard C ABI: redirected by elf2rom to the native .zisk keccak256.
    zkvm_keccak256(data, size, reinterpret_cast<zkvm_keccak256_hash*>(hash.bytes));
#else
    keccak256(hash.word64s, data, size);
#endif
    return hash;
}

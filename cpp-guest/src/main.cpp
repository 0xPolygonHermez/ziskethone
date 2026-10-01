// ZisK guest entry point: stateless re-execution of an Ethereum block.
//
// Reads a single private-input stream produced by `rust-input-gen`, replays
// the block against a ZiskStateDB, verifies the pre-execution state root
// against `consensus.parent_hash()`, recomputes the post-execution state
// root and the execution-layer block hash of the block under proof, and
// emits that block hash as the sole public output.
//
// The block-validation pipeline itself lives in `run` (see
// zeg/run.hpp) so it can be shared with the host-side C FFI wrapper.
// `main()` only does I/O: slurp the ZEG0 container into a buffer, run the
// pipeline, and emit the resulting 32-byte execution block hash.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#if defined(ZEG_ZISK)
#include "zeg/zisk_io.hpp"
#else
#include <fstream>
#endif

#include <evmc/evmc.hpp>

#include "zeg/binary_format.hpp"     // kMagic, kVersion
#include "zeg/fatal.hpp"
#include "zeg/run.hpp"

namespace {

// ===== I/O =====

// Slurp the input into an 8-byte-aligned static buffer and return a span
// (pointer + length) covering the whole ZEG0 container, starting at the
// magic. The buffer is 8-byte aligned so the typed reads downstream
// constructors perform via std::assume_aligned<8> stay valid.
struct InputBuffer {
    const uint8_t* ptr;
    size_t         len;
};
InputBuffer read_input_buffer(const char* path);

// Emit a 32-byte value to ZisK as a public output.
void emit_public_output(const uint8_t value[32]);

// Print the computed hash, the expected one when there is one, and the verdict.
// Same label width on every row so the hashes line up column by column.
void report_block_hash(const uint8_t computed[32], const uint8_t* expected);

// Parse a 0x-prefixed-or-bare 32-byte hex hash. Returns false if it isn't one.
bool parse_hash_hex(const char* hex, uint8_t out[32]);

} // namespace

#if defined(ZEG_ZISK)
int main() {
    // 1. Read the input from the ZisK memory-mapped input region.
    const InputBuffer in = read_input_buffer(nullptr);
#else
int main(int argc, char** argv) {
    // 1. Read the entire input stream from the file path passed on the command
    //    line. An optional second argument is the block hash this input is
    //    expected to produce, which the run then reports on. Only the host has
    //    it: passing the value to the ELF would mean putting it in the input,
    //    and the input format stays untouched.
    if (argc < 2) {
        zeg::fatal("usage: zisk_eth_guest <input-file> [expected-block-hash]");
    }
    const InputBuffer in = read_input_buffer(argv[1]);
    const char* const expected_hex = argc >= 3 ? argv[2] : nullptr;
#endif

    // 2. Run the full stateless block validation on the in-memory container.
    //    This parses every section, verifies the pre-execution state root,
    //    executes the block, recomputes the post-execution state root, builds
    //    the header, and computes the execution-layer block hash.
    uint8_t execution_block_hash[32] = {};
    const int rc = zeg::run(in.ptr, in.len, execution_block_hash);

    // A nonzero rc means run returned early without writing a hash because
    // the `ZEG_STAGE` debug selector requested a partial run (it already
    // printed its diagnostics). Bad witnesses fatal inside run rather than
    // returning, so the only nonzero rc is `kRunNoHashPartialStage` and the
    // happy path is rc == 0. Exit without emitting a (garbage) public output.
    if (rc != 0) {
        return 0;
    }

    // 3. Emit the execution-layer block hash as the sole public output.
    emit_public_output(execution_block_hash);

    // 4. Report the hash, next to the expected one when the host caller passed
    //    it on the command line. Under ZisK there is no command line and the
    //    input format carries no expected hash, so the ELF prints the computed
    //    row alone — which is also the "the run completed" signal on screen.
    //    On the host this goes to stderr, leaving the `0x<64 hex>` line on
    //    stdout (what the scripts parse) untouched.
    const uint8_t* expected_ptr = nullptr;
#if !defined(ZEG_ZISK)
    uint8_t expected[32];
    if (expected_hex != nullptr) {
        expected_ptr = parse_hash_hex(expected_hex, expected) ? expected : nullptr;
        if (expected_ptr == nullptr) {
            std::fprintf(stderr, "block_hash expected: not 32 hex bytes: %s\n",
                         expected_hex);
        }
    }
#endif
    report_block_hash(execution_block_hash, expected_ptr);

    return 0;
}

namespace {

#if defined(ZEG_ZISK)
InputBuffer read_input_buffer(const char* /*path*/) {
    // ZisK: the input lives in the memory-mapped input region, already
    // 8-byte aligned (it follows a u64 length word). No file, no copy.
    const zeg::zisk::Input in = zeg::zisk::read_input();
    if (in.len < 8) {
        zeg::fatal("read_input_buffer: input too small for magic");
    }
    return InputBuffer{in.ptr, in.len};
}
#else
InputBuffer read_input_buffer(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        zeg::fatal("read_input_buffer: failed to open input file");
    }
    const std::streamsize size = f.tellg();
    if (size < 8) {
        zeg::fatal("read_input_buffer: input file too small for magic");
    }
    f.seekg(0);

    // Back the buffer with std::vector<uint64_t> so its data() is
    // 8-byte aligned — downstream constructors do
    // std::assume_aligned<8> on cursor reads. The static keeps the
    // bytes alive for the rest of main().
    static std::vector<uint64_t> raw;
    raw.resize((static_cast<size_t>(size) + 7) / 8);
    if (!f.read(reinterpret_cast<char*>(raw.data()), size)) {
        zeg::fatal("read_input_buffer: short read");
    }
    const auto* base = reinterpret_cast<const uint8_t*>(raw.data());
    return InputBuffer{base, static_cast<size_t>(size)};
}
#endif  // ZEG_ZISK

bool parse_hash_hex(const char* hex, uint8_t out[32]) {
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }
    // Length first: the loop below indexes hex[0..64), so a shorter string would
    // be read past its end before the parse ever got to fail.
    if (std::strlen(hex) != 64) {
        return false;
    }
    for (int i = 0; i < 32; ++i) {
        unsigned byte;
        if (std::sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return false;
        }
        out[i] = static_cast<uint8_t>(byte);
    }
    return true;
}

void report_block_hash(const uint8_t computed[32], const uint8_t* expected) {
#if defined(ZEG_ZISK)
    auto put   = [](const char* s) { zeg::zisk::uart_puts(s); };
    auto put_h = [](const uint8_t* h) { zeg::zisk::uart_put_hex(h, 32); };
#else
    auto put   = [](const char* s) { std::fprintf(stderr, "%s", s); };
    auto put_h = [](const uint8_t* h) {
        for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", h[i]);
    };
#endif
    // "computed" and "expected" are the same width, so the two 0x columns line
    // up and a single differing digit is visible at a glance.
    put("block_hash computed 0x");
    put_h(computed);
    put("\n");
    if (expected == nullptr) {
        return;
    }
    put("block_hash expected 0x");
    put_h(expected);
    put(std::memcmp(computed, expected, 32) == 0 ? "\nblock_hash MATCH\n"
                                                 : "\nblock_hash MISMATCH\n");
}

void emit_public_output(const uint8_t value[32]) {
#if defined(ZEG_ZISK)
    // ZisK: write the 32-byte block hash to the public-output region as
    // 8 u32 slots (the value attested by the proof).
    zeg::zisk::set_output_bytes32(value);
#else
    // Host-build placeholder for the ZisK public-output API: print
    // the 32-byte value as lowercase hex with a 0x prefix, one line.
    std::printf("0x");
    for (int i = 0; i < 32; ++i) {
        std::printf("%02x", value[i]);
    }
    std::printf("\n");
#endif
}

} // namespace

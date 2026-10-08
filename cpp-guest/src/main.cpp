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

} // namespace

#if defined(ZEG_ZISK)
int main() {
    // 1. Read the input from the ZisK memory-mapped input region.
    const InputBuffer in = read_input_buffer(nullptr);
#else
int main(int argc, char** argv) {
    // 1. Read the entire input stream from the file path passed on
    //    the command line.
    if (argc < 2) {
        zeg::fatal("usage: zisk_eth_guest <input-file>");
    }
    const InputBuffer in = read_input_buffer(argv[1]);
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

#include "zeg/ssz.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#include "zeg/fatal.hpp"
#include "zeg/sha256.hpp"

namespace zeg::ssz {

namespace {

constexpr unsigned kMaxDepth = 64;

uint64_t chunk_count(std::size_t n_bytes) noexcept { return (n_bytes + 31) / 32; }

// ceil(log2(n)) — the depth of a tree with next_pow2(n) leaves (0 for n <= 1).
unsigned depth_for(uint64_t n) noexcept {
    unsigned d = 0;
    while (d < 64 && (uint64_t{1} << d) < n) ++d;
    return d;
}

// Bytes packed into zero-padded 32-byte chunks.
std::vector<Chunk> pack(std::span<const uint8_t> bytes) {
    std::vector<Chunk> chunks(chunk_count(bytes.size()));
    if (!bytes.empty()) std::memcpy(chunks.data(), bytes.data(), bytes.size());
    return chunks;
}

}  // namespace

Chunk hash(const Chunk& a, const Chunk& b) noexcept {
    uint8_t buf[64];
    std::memcpy(buf, a.bytes, 32);
    std::memcpy(buf + 32, b.bytes, 32);
    return sha256_bytes32(buf, sizeof(buf));
}

const Chunk& zero_hash(unsigned depth) noexcept {
    static const std::array<Chunk, kMaxDepth + 1> table = [] {
        std::array<Chunk, kMaxDepth + 1> t{};
        for (unsigned i = 0; i < kMaxDepth; ++i) t[i + 1] = hash(t[i], t[i]);
        return t;
    }();
    return table[depth];
}

Chunk merkleize(std::span<const Chunk> chunks, uint64_t limit) noexcept {
    if (chunks.size() > limit) fatal("ssz: merkleize input exceeds limit");
    const unsigned depth = depth_for(limit);
    if (chunks.empty()) return zero_hash(depth);

    // Hash level by level; an odd tail pairs with the zero subtree.
    std::vector<Chunk> level(chunks.begin(), chunks.end());
    std::size_t n = level.size();
    for (unsigned d = 0; d < depth; ++d) {
        const std::size_t half = (n + 1) / 2;
        for (std::size_t i = 0; i < half; ++i) {
            const Chunk& right = 2 * i + 1 < n ? level[2 * i + 1] : zero_hash(d);
            level[i] = hash(level[2 * i], right);
        }
        n = half;
    }
    return level[0];
}

Chunk merkleize_progressive(std::span<const Chunk> chunks) noexcept {
    // Subtree roots for chunks[0..1), [1..5), [5..21), ..., folded from the
    // end onto the terminating zero chunk.
    std::vector<Chunk> subtrees;
    uint64_t width = 1;
    while (!chunks.empty()) {
        const std::size_t take = std::min<uint64_t>(width, chunks.size());
        subtrees.push_back(merkleize(chunks.first(take), width));
        chunks = chunks.subspan(take);
        width *= 4;
    }
    Chunk root{};
    for (std::size_t i = subtrees.size(); i-- > 0;) root = hash(subtrees[i], root);
    return root;
}

Chunk mix_in_length(const Chunk& root, uint64_t length) noexcept {
    return hash(root, uint64_root(length));
}

Chunk mix_in_active_fields(const Chunk& root, unsigned n_active) noexcept {
    if (n_active == 0 || n_active > 256) fatal("ssz: bad active_fields count");
    Chunk bits{};
    for (unsigned i = 0; i < n_active; ++i) bits.bytes[i / 8] |= uint8_t(1u << (i % 8));
    return hash(root, bits);
}

Chunk uint64_root(uint64_t v) noexcept {
    Chunk c{};
    for (unsigned i = 0; i < 8; ++i) c.bytes[i] = uint8_t(v >> (8 * i));
    return c;
}

Chunk uint256_root(const evmc::uint256be& v) noexcept {
    Chunk c{};
    for (unsigned i = 0; i < 32; ++i) c.bytes[i] = v.bytes[31 - i];
    return c;
}

Chunk byte_vector_root(std::span<const uint8_t> bytes) noexcept {
    const auto chunks = pack(bytes);
    return merkleize(chunks, chunks.size());
}

Chunk byte_list_root(std::span<const uint8_t> bytes, uint64_t max_bytes) noexcept {
    if (bytes.size() > max_bytes) fatal("ssz: byte list exceeds limit");
    const auto chunks = pack(bytes);
    return mix_in_length(merkleize(chunks, chunk_count(max_bytes)), bytes.size());
}

Chunk progressive_byte_list_root(std::span<const uint8_t> bytes) noexcept {
    const auto chunks = pack(bytes);
    return mix_in_length(merkleize_progressive(chunks), bytes.size());
}

}  // namespace zeg::ssz

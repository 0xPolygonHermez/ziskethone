// Known-answer tests for zeg/ssz.hpp. Expected roots were generated with
// remerkleable via execution-specs @3ebcb5d (the EIP-8025 reference), e.g.
// ProgressiveList[Bytes32](...).hash_tree_root().
//
//   cmake --build cpp-guest/build --target ssz_test && cpp-guest/build/ssz_test

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "zeg/ssz.hpp"

using zeg::ssz::Chunk;

namespace {

int failures = 0;

std::string hex(const Chunk& c) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (auto b : c.bytes) {
        s += d[b >> 4];
        s += d[b & 15];
    }
    return s;
}

void check(const char* what, std::size_t n, const Chunk& got, const char* want) {
    if (hex(got) != want) {
        std::printf("FAIL %s n=%zu: got %s want %s\n", what, n, hex(got).c_str(), want);
        ++failures;
    }
}

std::vector<uint8_t> pattern(std::size_t n) {
    std::vector<uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = uint8_t(i * 7 + 3);
    return v;
}

struct Vec {
    std::size_t n;
    const char* root;
};

// ProgressiveList[Bytes32] with element i = bytes([i + 1]) * 32.
constexpr Vec kProgressiveList[] = {
    {0, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"},
    {1, "a21da97c8a597221c87c9ea5ecdfbd860fcd52fd6fb5b001723f6437856c8df1"},
    {2, "9a4badc45a45e9dd4b131c2c1aaff8a054527d8db40d2a7cd07e8f0f02a8232b"},
    {5, "183886e81b2e887d5960b2fa49b3464eabee62ec55ff5e6ee6f7e0495d8a01d1"},
    {6, "690beb7f075e2dc91699aa3ee9354687772923889ce755458cb405ae95e34055"},
    {21, "93589633f10a1e8fe51bef0481731c7c19d7a87269127b6c6a19720668ee47da"},
    {22, "e79bdcda4e58dd09c4b855964e1f1c01c99e215b6e01602f5302763effaf8637"},
    {86, "c28edc150a5a74b370746c2392e5fa01207d384aaaad03b35d25bf6608e614b5"},
};

// ProgressiveByteList of pattern(n).
constexpr Vec kProgressiveByteList[] = {
    {0, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"},
    {1, "8aa673f3bfc7dae693c4084d85ee7c1fd4d37b8916fd393a461cd0a85be19ab3"},
    {31, "d6a0f3fd60aab4605c8230de869270d7b6b4b37c0b86c5a83afe579ff0c148af"},
    {32, "c7270347f7a27f1d5c5c4bb174d36f771fafe10529f8c2971aab3c99a695ada6"},
    {33, "5572e016e4f1084df452a8ac0e13859fc64c50487a0795ebede0ef1d5f81e3c6"},
    {161, "4293e00ec78e044ab372f85908396a82d1b56a7e150aa3caadca1d4a9f10efca"},
    {1000, "02b749c1138c68d9ac775c93d4132b6cd638a70c8d655cf8caece23fe3cfa763"},
};

// ByteList[32] of pattern(n).
constexpr Vec kByteList32[] = {
    {0, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"},
    {5, "d915d09ce0b8618069179a8a7f806914c6768b5520a0ab89ad15a490989841f4"},
    {32, "9f985a74c8b780be5dc56a55ce50ff1e833a969cdf3f27a61a398c8bd942d9bb"},
};

// Default (all-zero / empty) EIP-8025 ExecutionPayload and ExecutionRequests.
constexpr const char* kDefaultExecutionPayload =
    "19e3b044dae3657cb2628406b78c61d8796fd490922f17441576a5bfbe8501df";
constexpr const char* kDefaultExecutionRequests =
    "87b69a306c8e430d0857f7c4ac5e27cecffa1108d43c2e5df7388056fea7a423";

}  // namespace

int main() {
    using namespace zeg::ssz;

    for (const auto& v : kProgressiveList) {
        std::vector<Chunk> chunks(v.n);
        for (std::size_t i = 0; i < v.n; ++i) std::memset(chunks[i].bytes, int(i + 1), 32);
        check("ProgressiveList[Bytes32]", v.n,
              mix_in_length(merkleize_progressive(chunks), v.n), v.root);
    }
    for (const auto& v : kProgressiveByteList) {
        check("ProgressiveByteList", v.n, progressive_byte_list_root(pattern(v.n)), v.root);
    }
    for (const auto& v : kByteList32) {
        check("ByteList[32]", v.n, byte_list_root(pattern(v.n), 32), v.root);
    }

    const Chunk zero{};
    const Chunk empty_list = mix_in_length(merkleize_progressive({}), 0);
    const std::vector<uint8_t> bloom(256);
    const Chunk payload_fields[19] = {
        zero, zero, zero, zero,
        byte_vector_root(bloom),
        zero, zero, zero, zero, zero,
        byte_list_root({}, 32),
        uint256_root(evmc::uint256be{}),
        zero,
        empty_list, empty_list,
        zero, zero,
        progressive_byte_list_root({}),
        zero,
    };
    check("ExecutionPayload()", 19,
          mix_in_active_fields(merkleize_progressive(payload_fields), 19),
          kDefaultExecutionPayload);
    const Chunk request_fields[5] = {empty_list, empty_list, empty_list, empty_list, empty_list};
    check("ExecutionRequests()", 5,
          mix_in_active_fields(merkleize_progressive(request_fields), 5),
          kDefaultExecutionRequests);

    if (failures == 0) std::printf("ssz_test: all passed\n");
    return failures == 0 ? 0 : 1;
}

// Host differential for the state-root ChainNode fold (audit A2 in
// GLAMSTERDAM.md / HEAP_BUDGET.md). input-gen spells a run of single-child
// branches (a revealed extension, or the shared prefix it splits off to place
// an absent key next to a leaf) as one Branch op per nibble. The guest used to
// keep a 224-byte BranchNode per nibble, so an author grinding keys with long
// shared hashed prefixes could blow the heap; now one ChainNode holds the whole
// run and must fold to EXACTLY the same trie node the nested branches did.
//
// This test includes ../src/state_root.cpp for its file-internal fold helpers
// (reduce_branch, chain_result, finalize, pack_extension), so the CMake target
// must NOT also link that object. It builds k nested single-child BranchNodes,
// folds them the old way, folds the same run as one ChainNode, and checks the
// resulting trie hashes are identical (and equal to an independent reference).

#include "zeg/seeded_hash.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

#include "../src/state_root.cpp"  // file-internal fold helpers (anon namespace)

// Inside namespace zeg so the anonymous-namespace helpers of state_root.cpp
// (EvalCtx, ValueSet, reduce_branch, chain_result, finalize, pack_*) and the
// zeg trie types are visible unqualified.
namespace zeg {
namespace {

int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// An EvalCtx wired to empty tables; only .stream and .aux are exercised here
// (PoolHash reads the stream; a PhantomLeaf child sits in aux).
struct Fixture {
    zeg::Accounts accounts;
    zeg::Storages storages;
    BranchNodes   branch_nodes;
    AuxNodes      aux;
    ChainNodes    chains;
    std::vector<uint8_t> stream;

    explicit Fixture(const zeg::HashSeed& s)
        : accounts(s), storages(s), stream(64, 0) {}

    EvalCtx ctx() { return EvalCtx{accounts, storages, branch_nodes, aux, chains, stream.data()}; }
};

bool eq(const evmc::bytes32& a, const evmc::bytes32& b) {
    return std::memcmp(a.bytes, b.bytes, 32) == 0;
}

PackedPath packed(const std::vector<uint8_t>& nibs) {
    PackedPath p;
    for (std::size_t i = nibs.size(); i-- > 0;) p.prepend(nibs[i]);
    return p;
}

// Fold a run of `nibs` single-child branches the old way: build nested
// BranchNodes bottom-up (each resolving the one below via result_ptr) and
// reduce_branch each. `innermost` is the child of the deepest branch.
evmc::bytes32 nested_hash(Fixture& fx, const std::vector<uint8_t>& nibs, Child innermost) {
    const std::size_t k = nibs.size();
    fx.branch_nodes.release();
    for (std::size_t j = 0; j < k; ++j) fx.branch_nodes.emplace_back();
    for (std::size_t jj = k; jj-- > 0;) {
        BranchNode& bn = fx.branch_nodes[jj];
        bn = BranchNode{};
        bn.tags = 0;  // single child, never the ">=2 Hash children" short-circuit
        const Child child = (jj + 1 == k) ? innermost : Child{NodeType::Branch, static_cast<uint32_t>(jj + 1)};
        bn.children[nibs[jj]] = child;
        bn.cached = reduce_branch(bn, fx.ctx(), ValueSet::Original);
    }
    return finalize(fx.branch_nodes[0].cached, fx.accounts, fx.storages, ValueSet::Original);
}

// Fold the same run as one ChainNode.
evmc::bytes32 chain_hash(Fixture& fx, const std::vector<uint8_t>& nibs, Child innermost) {
    ChainNode ch;
    ch.prefix = packed(nibs);
    ch.child  = innermost;
    ch.cached = chain_result(ch, fx.ctx());
    return finalize(ch.cached, fx.accounts, fx.storages, ValueSet::Original);
}

// Opaque-hash child (PoolHash into the stream): the run folds to one extension.
void chain_vs_nested_hash_child(const zeg::HashSeed& seed, std::mt19937_64& rng) {
    Fixture fx(seed);
    evmc::bytes32 H;
    for (auto& b : H.bytes) b = static_cast<uint8_t>(rng());
    std::memcpy(fx.stream.data(), H.bytes, 32);  // PoolHash idx 0

    for (int trial = 0; trial < 400; ++trial) {
        const std::size_t k = 1 + rng() % 40;  // run length (nibbles)
        std::vector<uint8_t> nibs(k);
        for (auto& n : nibs) n = static_cast<uint8_t>(rng() % 16);

        const Child child{NodeType::PoolHash, 0};
        const evmc::bytes32 nested = nested_hash(fx, nibs, child);
        const evmc::bytes32 chain  = chain_hash(fx, nibs, child);
        const evmc::bytes32 ref    = pack_extension(packed(nibs), H);  // independent reference

        CHECK(eq(nested, chain));
        CHECK(eq(chain, ref));
    }
    std::printf("chain_vs_nested (hash child) ok\n");
}

// Leaf child (PhantomLeaf in aux): the run merges its nibbles into the leaf path.
void chain_vs_nested_leaf_child(const zeg::HashSeed& seed, std::mt19937_64& rng) {
    for (int trial = 0; trial < 400; ++trial) {
        Fixture fx(seed);
        // A phantom leaf with its own path and value, placed in aux[0].
        std::vector<uint8_t> leaf_nibs(1 + rng() % 8);
        for (auto& n : leaf_nibs) n = static_cast<uint8_t>(rng() % 16);
        static uint8_t value[4] = {0x80, 0, 0, 0};
        value[0] = static_cast<uint8_t>(0x80 + (rng() % 0x30));
        PhantomLeafR pl;
        pl.path_nibbles = packed(leaf_nibs);
        pl.value_rlp = value;
        pl.value_len = 1;
        fx.aux.push_back(mk_node<PhantomLeafR>(pl));

        const std::size_t k = 1 + rng() % 30;
        std::vector<uint8_t> nibs(k);
        for (auto& n : nibs) n = static_cast<uint8_t>(rng() % 16);

        const Child child{NodeType::PhantomLeaf, 0};
        const evmc::bytes32 nested = nested_hash(fx, nibs, child);
        const evmc::bytes32 chain  = chain_hash(fx, nibs, child);

        // Reference: one phantom leaf whose path is the run nibbles followed by
        // the leaf's own nibbles.
        std::vector<uint8_t> merged = nibs;
        merged.insert(merged.end(), leaf_nibs.begin(), leaf_nibs.end());
        const evmc::bytes32 ref = pack_phantom_leaf(packed(merged), value, 1);

        CHECK(eq(nested, chain));
        CHECK(eq(chain, ref));
    }
    std::printf("chain_vs_nested (leaf child) ok\n");
}

int run_tests() {
    const uint8_t rs[16] = {0xa2,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    const HashSeed seed = HashSeed::derive(rs);
    std::mt19937_64 rng(12345);
    chain_vs_nested_hash_child(seed, rng);
    chain_vs_nested_leaf_child(seed, rng);
    std::printf(g_fail == 0 ? "ALL OK\n" : "%d FAILURES\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}

}  // anonymous namespace
}  // namespace zeg

int main() { return zeg::run_tests(); }

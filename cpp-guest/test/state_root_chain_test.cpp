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

#include <sys/wait.h>
#include <unistd.h>

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

// ---- audit 2026-11-17 Z-2: no ExtensionHash in the witness --------------------
//
// An ExtensionHash with an empty path, under a branch whose only other child is
// an absent key's empty leaf, reproduces the real extension in the old-root pass
// (reduce_branch prepends the slot nibble) but hashes as rlp([0x00, H]) once the
// key is created, so the post-state root is not canonical. input-gen never emits
// the op, so the guest rejects it outright, at any path length.

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

void put_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

// A state-witness section whose root is a Branch with one child, at nibble
// `slot`: a Hash child (what input-gen writes for an extension's still-hashed
// child), or a full ExtensionHash node with `ext_len` zero nibbles before H.
std::vector<uint8_t> one_child_witness(uint8_t slot, const evmc::bytes32& H, bool ext, uint64_t ext_len) {
    std::vector<uint8_t> w;
    put_u64(w, 64);         // numberOfNodes (an upper bound)
    put_u64(w, 0);          // numberOfAccounts
    put_u64(w, 0);          // numberOfStorages
    put_u64(w, UINT64_MAX); // firstSortedAccount: none
    put_u64(w, 4);          // Op::Branch
    put_u64(w, uint64_t{ext ? 2u : 1u} << (2 * slot));
    if (ext) {
        put_u64(w, 2);      // Op::ExtensionHash
        put_u64(w, ext_len);
        w.insert(w.end(), ((ext_len + 1) / 2 + 7) / 8 * 8, 0);
    }
    w.insert(w.end(), H.bytes, H.bytes + 32);
    return w;
}

evmc::bytes32 old_root_of(const std::vector<uint8_t>& w, const HashSeed& seed) {
    const uint8_t* cursor = w.data();
    set_stream_end(w.data() + w.size());
    Accounts accounts(seed);
    Storages storages(seed);
    StateRoot sr(cursor, accounts, storages);
    return sr.old_state_root();
}

void extension_hash_rejected(const HashSeed& seed) {
    evmc::bytes32 H;
    for (int i = 0; i < 32; ++i) H.bytes[i] = static_cast<uint8_t>(0x40 + i);
    const uint8_t x = 0x7;

    // The honest form folds to ext([x], H): keccak(rlp([hp([x], ext), H])).
    uint8_t rlp[35] = {0xe2, static_cast<uint8_t>(0x10 | x), 0xa0};
    std::memcpy(rlp + 3, H.bytes, 32);
    const evmc::bytes32 ref = keccak256_bytes32(rlp, sizeof(rlp));
    CHECK(eq(old_root_of(one_child_witness(x, H, false, 0), seed), ref));

    // ExtensionHash halts: the empty path the audit built, and a real one.
    for (const uint64_t len : {uint64_t{0}, uint64_t{1}, uint64_t{5}}) {
        const auto w = one_child_witness(x, H, true, len);
        CHECK(halts([&] { (void)old_root_of(w, seed); }));
    }
    std::printf("extension_hash_rejected ok\n");
}

int run_tests() {
    const uint8_t rs[16] = {0xa2,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    const HashSeed seed = HashSeed::derive(rs);
    std::mt19937_64 rng(12345);
    chain_vs_nested_hash_child(seed, rng);
    chain_vs_nested_leaf_child(seed, rng);
    extension_hash_rejected(seed);
    std::printf(g_fail == 0 ? "ALL OK\n" : "%d FAILURES\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}

}  // anonymous namespace
}  // namespace zeg

int main() { return zeg::run_tests(); }

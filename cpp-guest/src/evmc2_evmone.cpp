// evmc2_evmone.cpp — evmc2 adapter over evmone's baseline interpreter.
//
// Confines all evmone-internal coupling (baseline::analyze, the pre-analyzed
// baseline::execute overload, evmone::VM) to this translation unit. The adapter
// owns a real evmone VM and trampolines the standard evmc operations to it, while
// implementing the three evmc2 extensions (prepare / execute2 /
// release_pre_execution) on top of evmone baseline.

#include "evmc2_evmone.hpp"

#include <cstdlib>  // std::getenv
#include <cstring>  // std::memcpy, std::memset
#include <memory>
#include <unordered_map>
#include <vector>
#if !defined(ZEG_ZISK)
#include <iostream> // std::cerr
#endif

#include <evmone/baseline.hpp>  // CodeAnalysis, analyze, execute(VM&, …, CodeAnalysis&)
#include <evmone/evmone.h>      // evmc_create_evmone
#if !defined(ZEG_ZISK)
#include <evmone/tracing.hpp>   // create_instruction_tracer (ZEG_TRACE_OPCODES debug aid)
#endif
#include <evmone/vm.hpp>        // evmone::VM (the type behind the underlying vm)

namespace {

// The opaque evmc2_pre_execution* handed out by prepare() is a heap CodeAnalysis.
using Analysis = evmone::baseline::CodeAnalysis;

// ----- shared JUMPDEST maps across immutable-variant bytecodes -----
//
// Pool-sweeping blocks hand the guest hundreds of bytecodes that are one
// template with different immutables compiled in: same length, differing only
// inside PUSH data. Their code hashes differ, so the Contracts table cannot
// fold them, yet their JUMPDEST maps are bit-identical. Scanning costs ~4.7
// steps/byte; proving a variant parses like a scanned template costs ~0.75.
//
// Soundness: analyze_jumpdests walks instruction boundaries from offset 0 and
// only ever inspects a byte AT a boundary. So if two equal-length codes differ
// only at offsets that are PUSH data in the template, both walks visit the same
// boundaries and read equal bytes there — by induction, equal maps. `boundary`
// records those starts, which is what makes the condition checkable.
struct CodeTemplate {
    const uint8_t*              code = nullptr;  // the template's padded copy
    size_t                      size = 0;
    evmone::BitsetSpan          jumpdests{nullptr};
    std::unique_ptr<uint64_t[]> boundary;  // 1 bit/byte, built on first probe
};

// Below this a full scan is cheap enough that the bookkeeping cannot pay.
constexpr size_t kMinTemplateSize = 512;
// Few enough templates per size that a miss stays cheap.
constexpr size_t kTemplatesPerSize = 2;
// More diffs than a handful of immutables means unrelated codes of equal length.
constexpr size_t kMaxDiffWords = 256;

using TemplateRegistry = std::unordered_map<size_t, std::vector<CodeTemplate>>;

// `v` (and its first member `base`) sits at the start of the wrapper, so every
// callback recovers the wrapper from the evmc_vm* it receives.
struct EvmoneWrapper {
    evmc2_vm v;
    evmc_vm* impl;  // the real evmone VM (an evmone::VM)
    // Keyed by code size; a variant must match its template's length exactly.
    // Scoped to the VM, so it dies with the block. The bitsets it points at are
    // owned by CodeAnalysis objects released just before, and nothing reads the
    // registry after that.
    TemplateRegistry templates;
};

EvmoneWrapper* wrap(evmc_vm* vm) noexcept {
    return reinterpret_cast<EvmoneWrapper*>(vm);
}

// ----- base evmc operations: trampoline to the underlying evmone VM -----

void w_destroy(evmc_vm* vm) noexcept {
    auto* w = wrap(vm);
    w->impl->destroy(w->impl);
    delete w;
}

evmc_result w_execute(evmc_vm* vm, const evmc_host_interface* host,
                      evmc_host_context* ctx, evmc_revision rev,
                      const evmc_message* msg, uint8_t const* code,
                      size_t code_size) noexcept {
    auto* impl = wrap(vm)->impl;
    return impl->execute(impl, host, ctx, rev, msg, code, code_size);
}

evmc_capabilities_flagset w_get_capabilities(evmc_vm* vm) noexcept {
    auto* impl = wrap(vm)->impl;
    return impl->get_capabilities(impl);
}

evmc_set_option_result w_set_option(evmc_vm* vm, char const* name,
                                    char const* value) noexcept {
    auto* impl = wrap(vm)->impl;
    return impl->set_option ? impl->set_option(impl, name, value)
                            : EVMC_SET_OPTION_INVALID_NAME;
}

// ----- evmc2 extensions over evmone baseline -----

// Mark every instruction start of `t.code` — analyze_jumpdests's walk, recording
// boundaries instead of JUMPDESTs.
//
// COUPLING: the advance rule below must stay identical to evmone's, since the
// whole argument rests on both walks visiting the same positions. Nothing
// enforces it, which is what tools/jd_share_test.cpp is for: it accepts a pair
// only if evmone's own analysis of both agrees everywhere.
void build_boundary(CodeTemplate& t) {
    const size_t words = t.size / 64 + 1;
    t.boundary = std::make_unique<uint64_t[]>(words);  // value-initialized
    const auto* const begin = t.code;
    const auto* const end = begin + t.size;
    for (const auto* p = begin; p < end;) {
        const size_t i = static_cast<size_t>(p - begin);
        t.boundary[i / 64] |= uint64_t{1} << (i % 64);
        const auto op = *p;
        p += (static_cast<int8_t>(op) >= 0x60) ? (op - size_t{0x5e}) : 1;
    }
}

// Every differing byte in [from, to) must be PUSH data in the template.
bool diff_range_is_pushdata(CodeTemplate& t, const uint8_t* code, size_t from,
                            size_t to) {
    for (size_t i = from; i < to; ++i) {
        if (t.code[i] == code[i])
            continue;
        if (t.boundary == nullptr)  // built once, on the first real difference
            build_boundary(t);
        if (((t.boundary[i >> 6] >> (i & 63)) & 1u) != 0)
            return false;  // a differing byte at an instruction start
    }
    return true;
}

// True iff `code` (of t.size bytes) differs from the template only inside the
// template's PUSH data — the condition under which the two JUMPDEST maps are
// provably equal.
bool parses_like(CodeTemplate& t, const uint8_t* code) {
    const auto* const a = t.code;
    // The word-wise compare is the whole point; an unaligned code buffer would
    // pay MemAlign on every load, so fall back to a full scan instead.
    if (((reinterpret_cast<uintptr_t>(a) | reinterpret_cast<uintptr_t>(code)) & 7u) != 0)
        return false;

    const auto* const wa = reinterpret_cast<const uint64_t*>(a);
    const auto* const wb = reinterpret_cast<const uint64_t*>(code);
    const size_t nw = t.size / 8;
    size_t diff_words = 0;
    size_t i = 0;

    // Words nearly always match, so loop bookkeeping dominates: unroll by four.
    for (; i + 4 <= nw; i += 4) {
        if (wa[i] != wb[i] || wa[i + 1] != wb[i + 1] || wa[i + 2] != wb[i + 2] ||
            wa[i + 3] != wb[i + 3]) {
            for (size_t w = i; w < i + 4; ++w) {
                if (wa[w] != wb[w] && ++diff_words > kMaxDiffWords)
                    return false;
            }
            if (!diff_range_is_pushdata(t, code, i * 8, (i + 4) * 8))
                return false;
        }
    }
    for (; i < nw; ++i) {
        if (wa[i] == wb[i])
            continue;
        if (++diff_words > kMaxDiffWords)
            return false;
        if (!diff_range_is_pushdata(t, code, i * 8, (i + 1) * 8))
            return false;
    }
    return diff_range_is_pushdata(t, code, nw * 8, t.size);
}

// The padded buffer CodeAnalysis wants, minus the bitset words — a reusing
// variant borrows the template's map, so it allocates none of its own.
std::unique_ptr<uint8_t[]> padded_copy(const uint8_t* code, size_t code_size) {
    static constexpr size_t kPadding = 32 + 1;  // as in analyze_legacy
    auto storage = std::make_unique_for_overwrite<uint8_t[]>(code_size + kPadding);
    std::memcpy(storage.get(), code, code_size);
    std::memset(storage.get() + code_size, 0, kPadding);
    return storage;
}

evmc2_pre_execution* w_prepare(evmc_vm* vm, uint8_t const* code,
                               size_t code_size) noexcept {
    if (code_size >= kMinTemplateSize) {
        auto& bucket = wrap(vm)->templates[code_size];
        for (auto& t : bucket) {
            if (parses_like(t, code)) {
                auto* a = new Analysis(padded_copy(code, code_size), code_size,
                                       t.jumpdests);
                return reinterpret_cast<evmc2_pre_execution*>(a);
            }
        }
        auto* a = new Analysis(evmone::baseline::analyze(
            evmone::bytes_view{code, code_size}));
        if (bucket.size() < kTemplatesPerSize) {
            // Point at the analysis's own padded copy: it is 8-byte aligned and
            // lives exactly as long as the map borrowed from it.
            bucket.push_back(CodeTemplate{a->raw_code().data(), code_size,
                                          a->jumpdest_bitset(), nullptr});
        }
        return reinterpret_cast<evmc2_pre_execution*>(a);
    }
    auto* a = new Analysis(evmone::baseline::analyze(
        evmone::bytes_view{code, code_size}));
    return reinterpret_cast<evmc2_pre_execution*>(a);
}

void w_release(evmc_vm* /*vm*/, evmc2_pre_execution* pre) noexcept {
    delete reinterpret_cast<Analysis*>(pre);
}

evmc_result w_execute2(evmc_vm* vm, const evmc_host_interface* host,
                       evmc_host_context* ctx, evmc_revision rev,
                       const evmc_message* msg, uint8_t const* code,
                       size_t code_size, evmc2_pre_execution* pre) noexcept {
    auto* impl = wrap(vm)->impl;
    if (pre == nullptr)  // no prepared analysis → behave exactly like execute()
        return impl->execute(impl, host, ctx, rev, msg, code, code_size);
    const auto* analysis = reinterpret_cast<const Analysis*>(pre);
    return evmone::baseline::execute(*static_cast<evmone::VM*>(impl), *host, ctx,
                                     rev, *msg, *analysis);
}

}  // namespace

#if defined(ZEG_JUMPDEST_SHARING_TEST)
// Differential-test hook: runs the real template check over two same-length
// bytecodes. The property under test is one-sided — whenever this says yes,
// a fresh analysis of both must yield identical JUMPDEST maps.
extern "C" bool zeg_test_parses_like(const uint8_t* tmpl, const uint8_t* variant,
                                     size_t size) {
    CodeTemplate t{tmpl, size, evmone::BitsetSpan{nullptr}, nullptr};
    return parses_like(t, variant);
}
#endif

extern "C" evmc2_vm* evmc2_create_evmone(void) {
    evmc_vm* impl = evmc_create_evmone();
#if !defined(ZEG_ZISK)
    // Debug aid: ZEG_TRACE_OPCODES=1 attaches evmone's built-in per-opcode
    // instruction tracer (pc/op/gas/gasCost/stack/depth JSONL to stderr) for
    // the whole run. Not scoped to a single tx — bracket the target tx's
    // lines using the "TX %zu START"/"TX %zu gas_used=..." markers already
    // emitted in zisk_state_db.cpp's process_transactions loop. Host-only:
    // the ZisK build has no stderr/iostream (std::cerr isn't linkable in the
    // freestanding guest, and tracing to it would be meaningless in-circuit).
    if (std::getenv("ZEG_TRACE_OPCODES") != nullptr) {
        static_cast<evmone::VM*>(impl)->add_tracer(
            evmone::create_instruction_tracer(std::cerr));
    }
#endif
    // Aggregate-initialize: evmc_vm's abi_version/name/version are const, so they
    // must be set here rather than assigned afterwards.
    auto* w = new EvmoneWrapper{
        /*v=*/ {
            /*base=*/ {
                EVMC_ABI_VERSION,
                "evmone-evmc2",
                impl->version,
                w_destroy,
                w_execute,
                w_get_capabilities,
                w_set_option,
            },
            /*prepare=*/ w_prepare,
            /*execute2=*/ w_execute2,
            /*release_pre_execution=*/ w_release,
        },
        /*impl=*/ impl,
        /*templates=*/ {},
    };
    return &w->v;
}

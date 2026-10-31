// evmc2_evmone.cpp — evmc2 adapter over evmone's baseline interpreter.
//
// Confines all evmone-internal coupling (baseline::analyze, the pre-analyzed
// baseline::execute overload, evmone::VM) to this translation unit. The adapter
// owns a real evmone VM and trampolines the standard evmc operations to it, while
// implementing the three evmc2 extensions (prepare / execute2 /
// release_pre_execution) on top of evmone baseline.

#include "evmc2_evmone.hpp"

#include <cstdlib>  // std::getenv
#if !defined(ZEG_ZISK)
#include <iostream> // std::cerr
#endif

#include <evmone/baseline.hpp>  // CodeAnalysis, analyze, execute(VM&, …, CodeAnalysis&)
#include <evmone/evmone.h>      // evmc_create_evmone
#if !defined(ZEG_ZISK)
#include <evmone/tracing.hpp>   // create_instruction_tracer (ZEG_TRACE_OPCODES debug aid)
#endif
#include <evmone/vm.hpp>        // evmone::VM (the type behind the underlying vm)

#include "zeg/system_addresses.hpp"  // kMaxCodeSizeAmsterdam (slot sizing)
#include "zeg/tx_arena.hpp"          // FrameScratch (CREATE analyses)

namespace {

// The opaque evmc2_pre_execution* handed out by prepare() is a heap CodeAnalysis.
using Analysis = evmone::baseline::CodeAnalysis;

// `v` (and its first member `base`) sits at the start of the wrapper, so every
// callback recovers the wrapper from the evmc_vm* it receives.
struct EvmoneWrapper {
    evmc2_vm v;
    evmc_vm* impl;  // the real evmone VM (an evmone::VM)
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

evmc_set_option_result w_set_option(evmc_vm* vm, char const* name,
                                    char const* value) noexcept {
    auto* impl = wrap(vm)->impl;
    return impl->set_option ? impl->set_option(impl, name, value)
                            : EVMC_SET_OPTION_INVALID_NAME;
}

// ----- evmc2 extensions over evmone baseline -----

// Node offset inside a slot: the CodeAnalysis object, 8-byte aligned, followed
// by its padded-code + bitset storage.
inline constexpr size_t kAnalysisNode = (sizeof(Analysis) + 7) / 8 * 8;

// Bytes `analyze_into` writes for `code_size` bytes of code: padded code
// (code + 33, 8-aligned) + jumpdest bitset ((code+64)/64 words). Mirrors
// baseline_analysis.cpp's analyze_legacy layout.
inline constexpr size_t analyze_storage_bytes(size_t code_size) {
    const size_t padded = (code_size + 33 + 7) / 8 * 8;
    const size_t bitset_words = (code_size + 64) / 64;
    return padded + bitset_words * 8;
}
// Slot size = node + storage for the largest cacheable (deployed) code.
inline constexpr size_t kSlotBytes =
    kAnalysisNode + analyze_storage_bytes(zeg::kMaxCodeSizeAmsterdam);
// The fixed analysis cache is 1152 * kSlotBytes (the biggest heap reservation);
// if this moves, update scripts/heap_gate/sites.tsv and HEAP_BUDGET.md.
static_assert(kSlotBytes == 73808);  // heap-budget: evmone-analysis-slot

evmc2_pre_execution* w_prepare(evmc_vm* /*vm*/, uint8_t const* code,
                               size_t code_size, uint8_t* out_buf,
                               size_t out_cap) noexcept {
    if (out_buf != nullptr) {
        // Lay the CodeAnalysis node + its storage inside the caller's cache
        // slot (no heap growth). analyze_into writes the padded code + bitset
        // into out_buf+kAnalysisNode; the node adopts it. The cache owns the
        // slot and never destroys the node, so the node's unique_ptr deleter
        // (operator delete[], a no-op in the guest) never runs.
        auto* a = new (out_buf) Analysis(evmone::baseline::analyze_into(
            evmone::bytes_view{code, code_size}, out_buf + kAnalysisNode,
            out_cap - kAnalysisNode));
        return reinterpret_cast<evmc2_pre_execution*>(a);
    }
    auto* a = new Analysis(evmone::baseline::analyze(
        evmone::bytes_view{code, code_size}));
    return reinterpret_cast<evmc2_pre_execution*>(a);
}

void w_release(evmc_vm* /*vm*/, evmc2_pre_execution* pre) noexcept {
    // Only heap handles (out_buf == nullptr path) reach here; slot-backed
    // handles are owned by the analysis cache, which never calls release.
    delete reinterpret_cast<Analysis*>(pre);
}

// Analyses of code no cache keeps (CREATE init code, or no code at all), for
// the frame that runs it. execute() would analyze() onto the never-freed main
// heap, about the init code's size per CREATE for the whole block (audit H2);
// one allocation per frame from the tx arena still kept them all until the
// transaction ended (audit D). The analysis is dead once the frame returns
// (outputs are views of the frame's memory, patch 16), so it is handed back.
zeg::FrameScratch g_frame_scratch;

evmc_result w_execute2(evmc_vm* vm, const evmc_host_interface* host,
                       evmc_host_context* ctx, evmc_revision rev,
                       const evmc_message* msg, uint8_t const* code,
                       size_t code_size, evmc2_pre_execution* pre) noexcept {
    auto& evm = *static_cast<evmone::VM*>(wrap(vm)->impl);
    if (pre != nullptr) {
        return evmone::baseline::execute(evm, *host, ctx, rev, *msg,
                                         *reinterpret_cast<const Analysis*>(pre));
    }
    // What evmone's own execute() does, with the analysis in the scratch.
    const auto mark = g_frame_scratch.mark();
    const size_t bytes = kAnalysisNode + analyze_storage_bytes(code_size);
    auto* buf = static_cast<uint8_t*>(g_frame_scratch.alloc(bytes));
    const auto* analysis =
        reinterpret_cast<const Analysis*>(w_prepare(vm, code, code_size, buf, bytes));
    const evmc_result r = evmone::baseline::execute(evm, *host, ctx, rev, *msg, *analysis);
    g_frame_scratch.rewind(mark);
    return r;
}

void w_release_tx_buffers(evmc_vm* vm) noexcept {
    static_cast<evmone::VM*>(wrap(vm)->impl)->release_tx_buffers();  // patch 16
    g_frame_scratch.release();
}

}  // namespace

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
                .abi_version = EVMC_ABI_VERSION,
                .name        = "evmone-evmc2",
                .version     = impl->version,
                .destroy     = w_destroy,
                .execute     = w_execute,
                .set_option  = w_set_option,
            },
            /*prepare=*/ w_prepare,
            /*execute2=*/ w_execute2,
            /*release_pre_execution=*/ w_release,
            /*analysis_slot_bytes=*/ kSlotBytes,
            /*release_tx_buffers=*/ w_release_tx_buffers,
        },
        /*impl=*/ impl,
    };
    return &w->v;
}

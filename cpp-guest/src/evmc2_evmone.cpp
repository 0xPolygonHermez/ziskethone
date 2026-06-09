// evmc2_evmone.cpp — evmc2 adapter over evmone's baseline interpreter.
//
// Confines all evmone-internal coupling (baseline::analyze, the pre-analyzed
// baseline::execute overload, evmone::VM) to this translation unit. The adapter
// owns a real evmone VM and trampolines the standard evmc operations to it, while
// implementing the three evmc2 extensions (prepare / execute2 /
// release_pre_execution) on top of evmone baseline.

#include "evmc2_evmone.hpp"

#include <evmone/baseline.hpp>  // CodeAnalysis, analyze, execute(VM&, …, CodeAnalysis&)
#include <evmone/evmone.h>      // evmc_create_evmone
#include <evmone/vm.hpp>        // evmone::VM (the type behind the underlying vm)

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

evmc2_pre_execution* w_prepare(evmc_vm* /*vm*/, uint8_t const* code,
                               size_t code_size) noexcept {
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

extern "C" evmc2_vm* evmc2_create_evmone(void) {
    evmc_vm* impl = evmc_create_evmone();
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
    };
    return &w->v;
}

// tracer_stubs.cpp — null stubs for evmone's tracer factories.
//
// The guest never enables a tracer, so evmone/lib/evmone/tracing.cpp is excluded
// from the build (it pulls a large iostream dependency). Its only references from
// the rest of evmone are the three create_*_tracer factories in vm.cpp's
// set_option() (the "trace"/"histogram"/"instruction_counter" VM options, which
// the guest never sets). Provide trivial null-returning definitions so the link
// resolves without dragging in the tracer or <ostream>'s symbols.

#include <memory>
#include <ostream>
#include <string_view>

#include <lib/evmone/tracing.hpp>  // evmone::Tracer + the factory declarations

namespace evmone {

std::unique_ptr<Tracer> create_histogram_tracer(std::ostream&) { return nullptr; }
std::unique_ptr<Tracer> create_instruction_counter(std::string_view) { return nullptr; }
std::unique_ptr<Tracer> create_instruction_tracer(std::ostream&) { return nullptr; }

}  // namespace evmone

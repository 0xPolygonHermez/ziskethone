// stdcxx_stubs.cpp — link-only stubs for libstdc++ symbols that are referenced
// from DEAD code paths in the ZisK build and never execute:
//
//   * std::ostream / std::clog / operator<< — evmone's tracer plumbing
//     (vm.cpp set_option "trace"/"histogram", tracing.cpp). The guest never
//     enables tracing.
//   * std::basic_ofstream — the (host-only) instruction tracer file sink.
//   * std::pmr::monotonic_buffer_resource — used by modexp.cpp; the MODEXP
//     precompile is excluded/unused in this build.
//   * basic_string::_M_replace_cold — the cold path of a std::string mutation
//     only hit by the above formatting code.
//
// Each text symbol is given its exact mangled name via an asm label and a body
// that halts (so a real call — which must never happen — fails loudly rather
// than silently corrupting state). The data symbols (std::clog, the pmr
// vtable) are zeroed blobs of ample size.

#include <cstdint>

// Shared abort/termination from runtime.cpp (marchid-dispatched unimp / magic
// write). These stubs sit on dead code paths and must never actually run.
extern "C" [[noreturn]] void zeg_zisk_halt();

#define HALT_STUB(cname, mangled) \
    extern "C" void cname() asm(mangled); \
    extern "C" void cname() { zeg_zisk_halt(); }

// ostream member operator<< and _M_insert
HALT_STUB(z_os_ins_l,  "_ZNSo9_M_insertIlEERSoT_")
HALT_STUB(z_os_ins_m,  "_ZNSo9_M_insertImEERSoT_")
HALT_STUB(z_os_manip,  "_ZNSolsEPFRSt8ios_baseS0_E")
HALT_STUB(z_os_int,    "_ZNSolsEi")
HALT_STUB(z_os_short,  "_ZNSolsEs")
// free operator<< (char*, char, std::string)
HALT_STUB(z_os_pkc,    "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc")
HALT_STUB(z_os_c,      "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c")
HALT_STUB(z_os_str,    "_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKNSt7__cxx1112basic_stringIS4_S5_T1_EE")
// basic_ofstream ctor/dtor
HALT_STUB(z_ofs_ctor,  "_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode")
HALT_STUB(z_ofs_dtor,  "_ZNSt14basic_ofstreamIcSt11char_traitsIcEED1Ev")
// pmr
HALT_STUB(z_pmr_get,   "_ZNSt3pmr20get_default_resourceEv")
HALT_STUB(z_pmr_dtor,  "_ZNSt3pmr25monotonic_buffer_resourceD1Ev")
// std::string cold replace
HALT_STUB(z_str_cold,  "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE15_M_replace_coldEPcmPKcmm")

// Data symbols (never dereferenced): std::clog object and the pmr vtable.
char  z_clog_storage[512] asm("_ZSt4clog");
void* z_pmr_vtable[16] asm("_ZTVNSt3pmr25monotonic_buffer_resourceE") = {};

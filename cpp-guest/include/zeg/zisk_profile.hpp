// zisk_profile.hpp — ZisK profile markers for the C++ guest.
//
// C++ counterpart of ziskos' `profile_start!` / `profile_end!` family
// (zisk/ziskos/entrypoint/src/profile.rs). Brackets a region of guest code with
// a named tag; the emulator accumulates cost or steps between the two markers
// and prints the tally, which is how you attribute work to a function without a
// working ROI/symbol pass.
//
// Marker pair (transpile_profile_pattern):
//
//     csrs 0x81A, reg(tag)      -> profile x0, reg(tag), imm(id)
//     addi x0, x0, imm(id)
//
// `tag` is NOT a C string: the emulator reads a 16-byte descriptor at that
// address — an 8-byte data pointer followed by an 8-byte length — because
// ziskos passes a Rust `&str`, which is exactly that pair. `Tag` below has that
// layout, and the ZISK_PROFILE_* macros build a static one per call site so the
// descriptor outlives the marker.
//
// The markers cost one zisk instruction each and are only meaningful under the
// emulator's stats; leave them out of the code you actually prove.

#pragma once

#include <cstddef>

#if defined(ZEG_ZISK)

namespace zeg::zisk {

// What the emulator reads at the marker's operand: a Rust `&str`.
struct ProfileTag {
    const char* data;
    size_t      len;
};

// Marker kinds, from zisk_definitions::PROFILE_*_ID. `cost` and `steps` pick
// which quantity is accumulated; the `report` variants keep the tally for the
// end-of-run report instead of printing it when the region closes.
enum ProfileId : int {
    kProfileStartCost        = 1,
    kProfileEndCost          = 2,
    kProfileReportStartCost  = 3,
    kProfileReportEndCost    = 4,
    kProfileStartSteps       = 5,
    kProfileEndSteps         = 6,
    kProfileReportStartSteps = 7,
    kProfileReportEndSteps   = 8,
};

template <ProfileId Id>
inline void zisk_profile(const ProfileTag* tag) {
    asm volatile("csrs 0x81A, %[tag]\n\taddi x0, x0, %[id]"
                 :
                 : [tag] "r"(tag), [id] "I"(int(Id))
                 : "memory");
}

}  // namespace zeg::zisk

// Bracket a region. The tag is a bare identifier, as in ziskos, and becomes a
// static descriptor at the call site.
#define ZISK_PROFILE_MARK(id, name)                                            \
    do {                                                                       \
        static const ::zeg::zisk::ProfileTag zisk_profile_tag_{#name,          \
                                                               sizeof(#name) - 1}; \
        ::zeg::zisk::zisk_profile<id>(&zisk_profile_tag_);                     \
    } while (0)

#define ZISK_PROFILE_START(name) ZISK_PROFILE_MARK(::zeg::zisk::kProfileStartCost, name)
#define ZISK_PROFILE_END(name)   ZISK_PROFILE_MARK(::zeg::zisk::kProfileEndCost, name)
#define ZISK_PROFILE_STEPS_START(name) \
    ZISK_PROFILE_MARK(::zeg::zisk::kProfileStartSteps, name)
#define ZISK_PROFILE_STEPS_END(name) \
    ZISK_PROFILE_MARK(::zeg::zisk::kProfileEndSteps, name)
#define ZISK_PROFILE_REPORT_START(name) \
    ZISK_PROFILE_MARK(::zeg::zisk::kProfileReportStartCost, name)
#define ZISK_PROFILE_REPORT_END(name) \
    ZISK_PROFILE_MARK(::zeg::zisk::kProfileReportEndCost, name)
#define ZISK_PROFILE_REPORT_STEPS_START(name) \
    ZISK_PROFILE_MARK(::zeg::zisk::kProfileReportStartSteps, name)
#define ZISK_PROFILE_REPORT_STEPS_END(name) \
    ZISK_PROFILE_MARK(::zeg::zisk::kProfileReportEndSteps, name)

#else  // !ZEG_ZISK — the markers vanish on the host build.

#define ZISK_PROFILE_START(name)              ((void)0)
#define ZISK_PROFILE_END(name)                ((void)0)
#define ZISK_PROFILE_STEPS_START(name)        ((void)0)
#define ZISK_PROFILE_STEPS_END(name)          ((void)0)
#define ZISK_PROFILE_REPORT_START(name)       ((void)0)
#define ZISK_PROFILE_REPORT_END(name)         ((void)0)
#define ZISK_PROFILE_REPORT_STEPS_START(name) ((void)0)
#define ZISK_PROFILE_REPORT_STEPS_END(name)   ((void)0)

#endif  // ZEG_ZISK

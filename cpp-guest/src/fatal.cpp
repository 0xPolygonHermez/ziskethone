#include "zeg/fatal.hpp"

#include <cstdlib>
#if !defined(ZEG_ZISK)
#include <cstdio>
#endif

namespace zeg {

[[noreturn]] void fatal(const char* msg) {
#if !defined(ZEG_ZISK)
    std::fprintf(stderr, "guest: %s\n", msg);
#else
    (void)msg;
#endif
    std::abort();
}

} // namespace zeg

#include "zeg/fatal.hpp"

#include <cstdio>
#include <cstdlib>

namespace zeg {

[[noreturn]] void fatal(const char* msg) {
    std::fprintf(stderr, "guest: %s\n", msg);
    std::abort();
}

} // namespace zeg

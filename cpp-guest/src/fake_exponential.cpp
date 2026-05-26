#include "zeg/fake_exponential.hpp"

namespace zeg {

intx::uint256 fake_exponential(uint64_t factor,
                               uint64_t numerator,
                               uint64_t denominator) {
    const intx::uint256 num_u   = intx::uint256{numerator};
    const intx::uint256 denom_u = intx::uint256{denominator};
    intx::uint256 output    = 0;
    intx::uint256 num_accum = intx::uint256{factor} * denom_u;
    intx::uint256 i         = 1;
    while (num_accum > 0) {
        output    += num_accum;
        num_accum = (num_accum * num_u) / (denom_u * i);
        i        += 1;
    }
    return output / denom_u;
}

} // namespace zeg

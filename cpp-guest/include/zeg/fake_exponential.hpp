// EIP-4844 `fake_exponential` — used to derive the blob base fee from
// `excess_blob_gas`. Reference Python:
//
//   def fake_exponential(factor, numerator, denominator):
//       output = 0
//       numerator_accum = factor * denominator
//       i = 1
//       while numerator_accum > 0:
//           output += numerator_accum
//           numerator_accum = (numerator_accum * numerator) //
//                             (denominator * i)
//           i += 1
//       return output // denominator
//
// All intermediate values fit in 256 bits for plausible inputs
// (excess_blob_gas stays in u64 range).

#pragma once

#include <cstdint>

#include <intx/intx.hpp>

namespace zeg {

intx::uint256 fake_exponential(uint64_t factor,
                               uint64_t numerator,
                               uint64_t denominator);

} // namespace zeg

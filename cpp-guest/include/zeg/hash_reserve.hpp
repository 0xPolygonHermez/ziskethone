// zeg/hash_reserve.hpp — integer-only stand-in for unordered_map::reserve.

#pragma once

#include <cstddef>

namespace zeg {

// Pre-size an EMPTY unordered_map/set for `n` elements without floating point.
//
// std::unordered_map::reserve(n) is inlined from the libstdc++ header as
// rehash(ceil(n / (double)max_load_factor)) — on the ZisK target that drags in
// the soft-float runtime (__divdf3 alone is ~2,200 steps per call). The
// bucket-count constructor instead reaches only _M_next_bkt, the out-of-line
// rehash-policy method zisk/runtime.cpp overrides with integer math. With
// the default max_load_factor of 1.0 (nothing in the guest changes it) the
// resulting bucket count and growth threshold are identical to reserve(n)'s.
//
// Precondition: m is empty — the move-assignment discards contents.
//
// The bucket-count constructor is passed the map's current hash and equality
// instances (m.hash_function()/m.key_eq()) so a *stateful* functor — e.g. the
// seeded universal hash in zeg/seeded_hash.hpp — survives the reserve. A plain
// `Map(n)` would default-construct the functor and silently drop the seed.
template <class Map>
inline void hash_reserve_empty(Map& m, std::size_t n) {
    m = Map(n, m.hash_function(), m.key_eq());
}

}  // namespace zeg

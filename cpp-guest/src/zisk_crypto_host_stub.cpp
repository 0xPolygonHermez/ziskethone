// Host-only weak stub for ZisK's secp256k1_ecdsa_verify. The real
// symbol comes from ZisK lib-c on the zkVM target; on the host build
// we don't link that, but we still need a definition so the executable
// links. The stub aborts via zeg::fatal if anything ever reaches it.
//
// `__attribute__((weak))` lets the ZisK lib-c symbol override this at
// link time on the zkVM target without any CMake gymnastics.

#include "zeg/zisk_crypto.hpp"

#include "zeg/fatal.hpp"

extern "C" __attribute__((weak)) int secp256k1_ecdsa_verify(
    const uint64_t*, const uint64_t*, const uint64_t*, const uint64_t*, uint64_t*) {
    zeg::fatal("secp256k1_ecdsa_verify: host stub reached (no ZisK runtime linked)");
    return -1;
}

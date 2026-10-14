// C FFI wrapper so the host can run ziskethone's block validation in-process.
// `out` receives the guest's public output: the EIP-8025
// new_payload_request_root (no longer the execution block hash).
#include <cstddef>
#include <cstdint>

#include "zeg/run.hpp"

extern "C" int zeg_run(const uint8_t* input, size_t len, uint8_t out[32]) {
    return zeg::run(input, len, out);
}

// memory.cpp — memory opcodes (MLOAD 0x51, MSTORE 0x52, MSTORE8 0x53,
// MSIZE 0x59, MCOPY 0x5e). Backed by the static EVMMem manager (evm_mem.hpp).
//
// Stub: handlers land here as they are implemented.

#include "detail.hpp"

namespace zevm {

void register_memory(InstrTable& /*t*/) {}

}  // namespace zevm

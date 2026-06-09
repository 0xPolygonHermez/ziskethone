// env.cpp — execution-environment & block-context opcodes (0x30..0x4f: ADDRESS,
// BALANCE, ORIGIN, CALLER, CALLVALUE, CALLDATA*, CODE*, GASPRICE, EXTCODE*,
// RETURNDATA*, EXTCODEHASH, BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, PREVRANDAO,
// GASLIMIT, CHAINID, SELFBALANCE, BASEFEE, BLOBHASH, BLOBBASEFEE).
//
// Stub: handlers land here as they are implemented.

#include "detail.hpp"

namespace zevm {

void register_env(InstrTable& /*t*/) {}

}  // namespace zevm

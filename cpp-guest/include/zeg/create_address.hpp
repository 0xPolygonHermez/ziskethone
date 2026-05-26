// Contract-address derivation helpers (CREATE, CREATE2 / EOFCREATE).
// Pure functions — no state — so they live outside ZiskStateDB.
//
// CREATE   (Yellow Paper §7):  keccak256(rlp([sender, sender_nonce]))[12:]
// CREATE2  (EIP-1014):         keccak256(0xff || sender || salt
//                                         || keccak256(init))[12:]
// EOFCREATE shares the CREATE2 formula; the EVM hands the appropriate
// init bytes via msg.code so the same helper applies.

#pragma once

#include <cstddef>
#include <cstdint>

#include <evmc/evmc.hpp>

namespace zeg {

evmc::address compute_create_address(const evmc::address& sender,
                                     uint64_t sender_nonce);

evmc::address compute_create2_address(const evmc::address& sender,
                                      const evmc::bytes32& salt,
                                      const uint8_t*       init_code,
                                      std::size_t          init_code_size);

} // namespace zeg

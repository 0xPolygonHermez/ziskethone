#include "zeg/create_address.hpp"

#include <cstring>

#include "zeg/keccak.hpp"
#include "zeg/rlp.hpp"

namespace zeg {

// CREATE address derivation (Yellow Paper §7):
//   address = keccak256(rlp([sender, sender_nonce]))[12:32]
// `sender_nonce` is the value BEFORE the create-time increment.
evmc::address compute_create_address(const evmc::address& sender,
                                     uint64_t sender_nonce) {
    using rlp::BytesView;
    const auto sender_rlp = rlp::encode(BytesView{sender.bytes, 20});
    const auto nonce_rlp  = rlp::encode_u64(sender_nonce);
    const auto list_rlp   = rlp::encode_list({
        BytesView{sender_rlp.data(), sender_rlp.size()},
        BytesView{nonce_rlp.data(),  nonce_rlp.size()},
    });
    const auto h = keccak256_bytes32(list_rlp.data(), list_rlp.size());
    evmc::address addr{};
    std::memcpy(addr.bytes, h.bytes + 12, 20);
    return addr;
}

// CREATE2 address derivation (EIP-1014; same formula for EOFCREATE,
// EIP-7620, just with the init container's bytes instead of the
// init-code bytes — the EVM hands us the appropriate bytes either way):
//   address = keccak256(0xff || sender || salt || keccak256(init))[12:32]
evmc::address compute_create2_address(const evmc::address& sender,
                                      const evmc::bytes32& salt,
                                      const uint8_t*       init_code,
                                      std::size_t          init_code_size) {
    const auto init_hash = keccak256_bytes32(init_code, init_code_size);
    uint8_t buf[1 + 20 + 32 + 32];
    buf[0] = 0xff;
    std::memcpy(buf + 1,  sender.bytes,    20);
    std::memcpy(buf + 21, salt.bytes,      32);
    std::memcpy(buf + 53, init_hash.bytes, 32);
    const auto h = keccak256_bytes32(buf, sizeof(buf));
    evmc::address addr{};
    std::memcpy(addr.bytes, h.bytes + 12, 20);
    return addr;
}

} // namespace zeg

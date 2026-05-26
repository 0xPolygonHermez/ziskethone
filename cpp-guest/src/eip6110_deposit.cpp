#include "zeg/eip6110_deposit.hpp"

#include <cstddef>
#include <cstdint>

#include <evmc/evmc.hpp>

#include "zeg/fatal.hpp"
#include "zeg/keccak.hpp"
#include "zeg/system_addresses.hpp"

namespace zeg {

namespace {

// Read a 32-byte big-endian uint at `p` as a size_t. Aborts via fatal
// if the value doesn't fit (upper 24 bytes non-zero). Used for ABI
// offsets/lengths.
std::size_t read_abi_uint32be_as_size(const uint8_t* p) {
    for (std::size_t i = 0; i < 24; ++i) {
        if (p[i] != 0) {
            fatal("DepositEvent ABI: integer field overflows size_t");
        }
    }
    std::size_t v = 0;
    for (std::size_t i = 24; i < 32; ++i) {
        v = (v << 8) | p[i];
    }
    return v;
}

// Read the i-th dynamic-`bytes` field from a Solidity-encoded event
// payload that consists entirely of `bytes` parameters. Returns
// (data_ptr, length). Aborts via fatal on truncation / corruption.
struct AbiBytesField { const uint8_t* data; std::size_t length; };

AbiBytesField abi_read_bytes_field(const uint8_t* data, std::size_t data_size,
                                   std::size_t field_index) {
    const std::size_t off_pos = field_index * 32;
    if (off_pos + 32 > data_size) {
        fatal("DepositEvent ABI: offset slot out of bounds");
    }
    const std::size_t offset = read_abi_uint32be_as_size(data + off_pos);
    if (offset + 32 > data_size) {
        fatal("DepositEvent ABI: length slot out of bounds");
    }
    const std::size_t length = read_abi_uint32be_as_size(data + offset);
    if (offset + 32 + length > data_size) {
        fatal("DepositEvent ABI: bytes payload out of bounds");
    }
    return AbiBytesField{data + offset + 32, length};
}

} // namespace

void extract_deposit_requests(std::span<const TxReceipt> receipts,
                              std::vector<uint8_t>&      out) {
    // keccak256("DepositEvent(bytes,bytes,bytes,bytes,bytes)").
    // Computed once on first call; cheap, and avoids a wrong hardcoded
    // value going undetected.
    static const evmc::bytes32 deposit_event_topic = [] {
        const char sig[] = "DepositEvent(bytes,bytes,bytes,bytes,bytes)";
        return keccak256_bytes32(reinterpret_cast<const uint8_t*>(sig),
                                 sizeof(sig) - 1);
    }();

    for (const auto& receipt : receipts) {
        for (const auto& log : receipt.logs) {
            if (log.address != kDepositContractAddress) continue;
            if (log.topics.empty())                       continue;
            if (log.topics[0] != deposit_event_topic)     continue;

            const uint8_t*    d   = log.data.data();
            const std::size_t dsz = log.data.size();
            const auto pubkey_f = abi_read_bytes_field(d, dsz, 0);
            const auto wc_f     = abi_read_bytes_field(d, dsz, 1);
            const auto amount_f = abi_read_bytes_field(d, dsz, 2);
            const auto sig_f    = abi_read_bytes_field(d, dsz, 3);
            const auto index_f  = abi_read_bytes_field(d, dsz, 4);
            if (pubkey_f.length != 48 || wc_f.length != 32 ||
                amount_f.length != 8  || sig_f.length != 96 ||
                index_f.length  != 8) {
                fatal("EIP-6110: DepositEvent field has wrong size");
            }
            out.insert(out.end(), pubkey_f.data, pubkey_f.data + 48);
            out.insert(out.end(), wc_f.data,     wc_f.data     + 32);
            out.insert(out.end(), amount_f.data, amount_f.data + 8);
            out.insert(out.end(), sig_f.data,    sig_f.data    + 96);
            out.insert(out.end(), index_f.data,  index_f.data  + 8);
        }
    }
}

} // namespace zeg

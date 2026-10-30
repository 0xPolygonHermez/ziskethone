#include "zeg/eip6110_deposit.hpp"

#include <cstddef>
#include <cstdint>

#include <evmc/evmc.hpp>

#include "zeg/fatal.hpp"
#include "zeg/keccak.hpp"
#include "zeg/system_addresses.hpp"

namespace zeg {

namespace {

// The deposit contract emits DepositEvent(bytes,bytes,bytes,bytes,bytes) with
// one fixed ABI layout. Like execution-specs `extract_deposit_data`, accept
// only that layout: 576 bytes, the five head offsets and the five length
// words at their canonical values. Any other encoding makes the block
// invalid. No offset is followed, so no offset arithmetic can overflow.
constexpr std::size_t kDepositEventSize = 576;

struct DepositField { std::size_t offset; std::size_t length; };
constexpr DepositField kDepositFields[5] = {
    {160, 48},  // pubkey
    {256, 32},  // withdrawal_credentials
    {320,  8},  // amount
    {384, 96},  // signature
    {512,  8},  // index
};

// True when the 32-byte big-endian word at `p` equals `v`.
bool abi_word_equals(const uint8_t* p, std::size_t v) {
    for (std::size_t i = 0; i < 32; ++i) {
        const auto want = i < 24 ? 0 : static_cast<uint8_t>(v >> (8 * (31 - i)));
        if (p[i] != want) return false;
    }
    return true;
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

            const uint8_t* d = log.data.data();
            if (log.data.size() != kDepositEventSize) {
                fatal("EIP-6110: DepositEvent has wrong size");
            }
            for (std::size_t i = 0; i < 5; ++i) {
                const auto& f = kDepositFields[i];
                if (!abi_word_equals(d + 32 * i, f.offset)) {
                    fatal("EIP-6110: DepositEvent field has wrong offset");
                }
                if (!abi_word_equals(d + f.offset, f.length)) {
                    fatal("EIP-6110: DepositEvent field has wrong size");
                }
            }
            for (const auto& f : kDepositFields) {
                out.insert(out.end(), d + f.offset + 32, d + f.offset + 32 + f.length);
            }
        }
    }
}

} // namespace zeg

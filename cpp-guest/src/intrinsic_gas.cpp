#include "zeg/intrinsic_gas.hpp"

#include "zeg/fatal.hpp"
#include "zeg/rlp.hpp"

namespace zeg {

namespace {

// EIP-2780 (Amsterdam): the 21000 base split by what the tx touches —
// TX_BASE for the sender, plus CREATE_ACCESS for a create, or the
// recipient's cold access and (with value) TX_VALUE_COST for a call.
// A self-transfer pays the base only (revm eip2780_base_to_value_gas).
int64_t eip2780_base(const Transactions::View& tx) {
    constexpr int64_t TX_BASE_COST        = 12000;
    constexpr int64_t TX_VALUE_COST       = 6000;
    constexpr int64_t COLD_ACCOUNT_ACCESS = 3000;   // EIP-8038
    constexpr int64_t CREATE_ACCESS       = 12000;  // EIP-8038: ACCOUNT_WRITE + COLD_ACCOUNT_ACCESS
    if (tx.to() == nullptr) return TX_BASE_COST + CREATE_ACCESS;
    if (*tx.to() == tx.sender()) return TX_BASE_COST;
    bool has_value = false;
    for (uint8_t b : tx.value().bytes) has_value |= (b != 0);
    return TX_BASE_COST + COLD_ACCOUNT_ACCESS + (has_value ? TX_VALUE_COST : 0);
}

}  // namespace

int64_t compute_intrinsic_gas(const Transactions::View& tx,
                              evmc_revision rev,
                              int64_t* calldata_floor) {
    using TxType = Transactions::Type;

    const bool    amsterdam = rev >= EVMC_AMSTERDAM;
    const int64_t base      = amsterdam ? eip2780_base(tx) : 21000;
    int64_t gas = (tx.to() == nullptr && !amsterdam) ? base + 32000 : base;

    // EIP-2028: 4 gas per byte, plus 12 more for each non-zero one.
    const auto data = tx.data();
    const auto nonzero = static_cast<int64_t>(count_nonzero_bytes(data));
    gas += static_cast<int64_t>(data.size()) * 4 + nonzero * 12;
    // EIP-3860 (Shanghai): 2 gas per 32-byte word of init code on
    // creation txs. Pre-Shanghai (Berlin/London/Paris) doesn't
    // charge this — applying it over-charges 14 gas on a 222-byte
    // init-code creation tx in test_contract_creation_transaction.
    if (tx.to() == nullptr && rev >= EVMC_SHANGHAI) {
        gas += static_cast<int64_t>((tx.data().size() + 31) / 32) * 2;
    }

    // EIP-2930 access list. Typed txs always carry one (possibly
    // empty, i.e. just `0xc0`); legacy txs don't.
    // Amsterdam: EIP-8038's per-item access cost (COLD_* − WARM_ACCESS:
    // 2900 / 2000) plus EIP-7981's 64 gas per access-list byte (20 per
    // address, 32 per key).
    const int64_t al_address_cost = amsterdam ? 2900 + 20 * 64 : 2400;
    const int64_t al_key_cost     = amsterdam ? 2000 + 32 * 64 : 1900;
    int64_t al_addresses = 0;
    int64_t al_keys      = 0;
    if (tx.type() != TxType::Legacy) {
        const auto outer = rlp::decode_item(tx.access_list_rlp());
        if (outer.kind != rlp::ItemKind::List) {
            fatal("access_list is not an RLP list");
        }
        rlp::ListIter it{outer.payload};
        while (it.has_next()) {
            const auto entry = it.next();
            if (entry.kind != rlp::ItemKind::List) {
                fatal("access_list entry is not an RLP list");
            }
            rlp::ListIter eit{entry.payload};
            if (!eit.has_next()) fatal("access_list entry missing address");
            (void)eit.next();
            ++al_addresses;
            if (!eit.has_next()) fatal("access_list entry missing keys");
            const auto keys = eit.next();
            if (keys.kind != rlp::ItemKind::List) {
                fatal("access_list storage-keys field is not an RLP list");
            }
            rlp::ListIter kit{keys.payload};
            while (kit.has_next()) {
                (void)kit.next();
                ++al_keys;
            }
        }
    }

    gas += al_addresses * al_address_cost + al_keys * al_key_cost;

    // EIP-7623 calldata floor: 10 per token (zero byte 1, non-zero 4).
    // Amsterdam: EIP-7976 makes every byte 4 tokens at 16 (64 gas per
    // byte), and EIP-7981 adds the access-list bytes at the same rate.
    if (calldata_floor != nullptr) {
        *calldata_floor =
            amsterdam
                ? base + 64 * (static_cast<int64_t>(data.size()) +
                               20 * al_addresses + 32 * al_keys)
                : base + (static_cast<int64_t>(data.size()) + nonzero * 3) * 10;
    }

    // EIP-7702 authorization list. View already counted entries while
    // reading the prover-supplied auth pubkeys — reuse that count
    // instead of re-walking the RLP.
    // Amsterdam (EIP-2780): REGULAR_PER_AUTH_BASE_COST = the tuple's 101
    // bytes at the 16/token floor rate + ecrecover + the authority's cold
    // access + two warm writes (101*16 + 3000 + 3000 + 200).
    if (tx.type() == TxType::SetCode) {
        const int64_t per_auth = amsterdam ? 101 * 16 + 3000 + 3000 + 2 * 100 : 25000;
        gas += per_auth * static_cast<int64_t>(tx.num_authorizations());
    }

    return gas;
}

} // namespace zeg

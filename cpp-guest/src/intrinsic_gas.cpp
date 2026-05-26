#include "zeg/intrinsic_gas.hpp"

#include "zeg/fatal.hpp"
#include "zeg/rlp.hpp"

namespace zeg {

int64_t compute_intrinsic_gas(const Transactions::View& tx) {
    using TxType = Transactions::Type;

    int64_t gas = (tx.to() == nullptr) ? 53000 : 21000;

    for (uint8_t b : tx.data()) {
        gas += (b == 0) ? 4 : 16;
    }
    if (tx.to() == nullptr) {
        gas += static_cast<int64_t>((tx.data().size() + 31) / 32) * 2;
    }

    // EIP-2930 access list. Typed txs always carry one (possibly
    // empty, i.e. just `0xc0`); legacy txs don't.
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
            gas += 2400;  // ACCESS_LIST_ADDRESS_COST
            if (!eit.has_next()) fatal("access_list entry missing keys");
            const auto keys = eit.next();
            if (keys.kind != rlp::ItemKind::List) {
                fatal("access_list storage-keys field is not an RLP list");
            }
            rlp::ListIter kit{keys.payload};
            while (kit.has_next()) {
                (void)kit.next();
                gas += 1900;  // ACCESS_LIST_STORAGE_KEY_COST
            }
        }
    }

    // EIP-7702 authorization list. View already counted entries while
    // reading the prover-supplied auth pubkeys — reuse that count
    // instead of re-walking the RLP.
    if (tx.type() == TxType::SetCode) {
        gas += 25000 * static_cast<int64_t>(tx.num_auth_pubkeys());
    }

    return gas;
}

} // namespace zeg

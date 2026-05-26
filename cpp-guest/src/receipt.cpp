#include "zeg/receipt.hpp"

#include "zeg/rlp.hpp"

namespace zeg {

std::vector<uint8_t> encode_receipt(const TxReceipt& r) {
    using rlp::BytesView;

    // Build the outer logs list: concat each log's RLP, then wrap.
    rlp::Bytes logs_payload;
    for (const auto& log : r.logs) {
        const auto addr_rlp = rlp::encode(BytesView{log.address.bytes, 20});

        // Topics: variable-count list of 32-byte strings.
        rlp::Bytes topics_payload;
        for (const auto& t : log.topics) {
            const auto t_rlp = rlp::encode(BytesView{t.bytes, 32});
            topics_payload.insert(topics_payload.end(),
                                  t_rlp.begin(), t_rlp.end());
        }
        const auto topics_list = rlp::encode_list_payload(
            BytesView{topics_payload.data(), topics_payload.size()});

        const auto data_rlp = rlp::encode(BytesView{log.data.data(),
                                                    log.data.size()});

        const auto log_rlp = rlp::encode_list({
            BytesView{addr_rlp},
            BytesView{topics_list},
            BytesView{data_rlp},
        });
        logs_payload.insert(logs_payload.end(),
                            log_rlp.begin(), log_rlp.end());
    }
    const auto logs_list = rlp::encode_list_payload(
        BytesView{logs_payload.data(), logs_payload.size()});

    const auto status_rlp  = rlp::encode_u64(r.status ? 1u : 0u);
    const auto cum_gas_rlp = rlp::encode_u64(r.cumulative_gas_used);
    const auto bloom_rlp   = rlp::encode(BytesView{r.logs_bloom.data(),
                                                   r.logs_bloom.size()});

    const auto body = rlp::encode_list({
        BytesView{status_rlp},
        BytesView{cum_gas_rlp},
        BytesView{bloom_rlp},
        BytesView{logs_list},
    });

    if (r.tx_type == Transactions::Type::Legacy) {
        return std::vector<uint8_t>(body.begin(), body.end());
    }
    std::vector<uint8_t> out;
    out.reserve(1 + body.size());
    out.push_back(static_cast<uint8_t>(r.tx_type));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

} // namespace zeg

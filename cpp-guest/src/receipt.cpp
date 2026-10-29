#include "zeg/receipt.hpp"

#include "zeg/fatal.hpp"
#include "zeg/rlp.hpp"

namespace zeg {

namespace {

// Encoded size of a list item with a `payload_len`-byte payload (same header
// length as a string's).
std::size_t list_size(std::size_t payload_len) { return rlp::item_size(payload_len); }

// Payload length of a log's RLP list: [address, [topics...], data].
std::size_t log_payload(const LogEntry& log) {
    const std::size_t topics = log.topics.size() * rlp::item_size(32);
    const std::size_t data =
        (log.data.size() == 1 && log.data[0] < 0x80) ? 1 : rlp::item_size(log.data.size());
    return rlp::item_size(20) + list_size(topics) + data;
}

std::size_t write_list_header(uint8_t* dst, std::size_t payload_len) {
    uint8_t hdr[5];
    const std::size_t n = rlp::detail::make_header<0xc0, 0xf7>(hdr, payload_len);
    __builtin_memcpy(dst, hdr, n);
    return n;
}

} // namespace

// Sized first, then written once into an exact buffer: a receipt can carry
// tens of KiB of log data, and under the guest's never-freeing allocator every
// intermediate copy would stay on the heap.
std::vector<uint8_t> encode_receipt(const TxReceipt& r) {
    std::size_t logs_payload = 0;
    for (const auto& log : r.logs) logs_payload += list_size(log_payload(log));

    uint8_t status_buf[9], cum_gas_buf[9];
    const std::size_t status_len  = rlp::write_u64(status_buf, r.status ? 1u : 0u);
    const std::size_t cum_gas_len = rlp::write_u64(cum_gas_buf, r.cumulative_gas_used);
    const std::size_t body_payload = status_len + cum_gas_len
                                   + rlp::item_size(r.logs_bloom.size())
                                   + list_size(logs_payload);
    const bool typed = r.tx_type != Transactions::Type::Legacy;

    std::vector<uint8_t> out(static_cast<std::size_t>(typed) + list_size(body_payload));
    uint8_t* p = out.data();
    if (typed) *p++ = static_cast<uint8_t>(r.tx_type);
    p += write_list_header(p, body_payload);
    __builtin_memcpy(p, status_buf, status_len);   p += status_len;
    __builtin_memcpy(p, cum_gas_buf, cum_gas_len); p += cum_gas_len;
    p += rlp::write_string(p, r.logs_bloom.data(), r.logs_bloom.size());
    p += write_list_header(p, logs_payload);
    for (const auto& log : r.logs) {
        p += write_list_header(p, log_payload(log));
        p += rlp::write_string(p, log.address.bytes, 20);
        p += write_list_header(p, log.topics.size() * rlp::item_size(32));
        for (const auto& t : log.topics) p += rlp::write_string(p, t.bytes, 32);
        p += rlp::write_string(p, log.data.data(), log.data.size());
    }
    if (p != out.data() + out.size()) fatal("encode_receipt: size mismatch");
    return out;
}

} // namespace zeg

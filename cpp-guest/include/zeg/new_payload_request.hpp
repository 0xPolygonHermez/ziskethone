// EIP-8025 `new_payload_request_root`: the SSZ hash_tree_root of the Engine
// API NewPayloadRequest of the block under proof — the guest's public output.
//
//   NewPayloadRequest(Container):
//     execution_payload:        ExecutionPayload  (ProgressiveContainer, 19 fields)
//     versioned_hashes:         ProgressiveList[Bytes32]
//     parent_beacon_block_root: Bytes32
//     execution_requests:       ExecutionRequests (ProgressiveContainer, 5 fields)
//
// Every field is taken from data the guest validated: the rebuilt header,
// its computed hash, the tx envelopes, the withdrawals, the requests and
// the BAL produced by execution. The Amsterdam schema is used for every
// fork; fields a fork lacks are empty / zero.

#pragma once

#include <evmc/evmc.hpp>

namespace zeg {

struct BlockHeader;
class ConsensusInfo;
class Transactions;
class ZiskStateDB;

evmc::bytes32 new_payload_request_root(const BlockHeader&   header,
                                       const evmc::bytes32& block_hash,
                                       const Transactions&  transactions,
                                       const ConsensusInfo& consensus,
                                       const ZiskStateDB&   state);

}  // namespace zeg

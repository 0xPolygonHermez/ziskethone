#!/usr/bin/env python3
"""Reference EIP-8025 new_payload_request_root for a block, from the spec.

Builds the Engine API NewPayloadRequest of block N with the execution-specs
classes and prints its SSZ hash_tree_root, to cross-check the guest's public
output (the last line of `zisk_eth_guest`).

Header, transactions and withdrawals come from the node (debug_getRawBlock),
or from a block RLP given with --block-rlp (e.g. an EEST fixture's
`blocks[i].rlp`).
The execution requests and the block access list are not served by the RPC,
so they are taken from the guest's `ZEG_DUMP_NPR=1` stderr and checked
against the header's requests_hash / block_access_list_hash.

Note: the guest follows consensus-specs gloas (and Lighthouse), where
NewPayloadRequest is a ProgressiveContainer and versioned_hashes a
List[.., 4096]. The execution-specs commit below predates that change, so
its root no longer matches the guest's.

Setup (execution-specs pinned to the EIP-8025 reference commit; its wheel
omits `execution_engine`, so the source tree is put on sys.path):

    git clone https://github.com/ethereum/execution-specs es-repo
    git -C es-repo checkout 3ebcb5d02126918eb2aad599b3cf286200d4f458
    python3 -m venv venv && venv/bin/pip install ./es-repo

Usage:

    ZEG_DUMP_NPR=1 ./cpp-guest/build/zisk_eth_guest build/block_input.bin 2> npr.txt
    venv/bin/python scripts/npr_root_ref.py --es-src es-repo/src \\
        --rpc-url http://localhost:8545 --block $BLK --npr-dump npr.txt
"""

import argparse
import hashlib
import json
import sys
import urllib.request


def rpc(url, method, params):
    req = urllib.request.Request(
        url,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as r:
        resp = json.load(r)
    if "error" in resp:
        sys.exit(f"{method}: {resp['error']}")
    return resp["result"]


def read_dump(path):
    requests, bal = [], b""
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) != 3 or parts[0] != "NPR":
                continue
            data = bytes.fromhex(parts[2][2:])
            if parts[1] == "request":
                requests.append(data)
            elif parts[1] == "bal":
                bal = data
    return requests, bal


def npr_root(raw_block, requests, bal):
    """(block_hash, new_payload_request_root) of an RLP block, given the
    block's type-prefixed request blobs and BAL RLP (b"" before Amsterdam).
    Needs the execution-specs src/ on sys.path."""
    import ethereum_rlp as rlp
    from ethereum.crypto.hash import keccak256
    from ethereum.forks.amsterdam.blocks import Withdrawal
    from ethereum.forks.amsterdam.execution_engine.requests import (
        decode_execution_requests,
    )
    from ethereum.forks.amsterdam.execution_engine.types import (
        ExecutionPayload,
        NewPayloadRequest,
    )
    from ethereum_types.bytes import Bytes, Bytes20, Bytes32, Bytes256
    from ethereum_types.numeric import U64, U256, Uint

    block = rlp.decode(raw_block)
    header, txs = block[0], block[1]
    withdrawals = block[3] if len(block) > 3 else []
    block_hash = keccak256(rlp.encode(header))
    h = lambda i: header[i] if len(header) > i else b""  # noqa: E731
    u = lambda b: int.from_bytes(b, "big")  # noqa: E731

    # Typed txs are RLP strings (the envelope); legacy txs are RLP lists.
    envelopes = [t if isinstance(t, bytes) else rlp.encode(t) for t in txs]
    versioned_hashes = []
    for env in envelopes:
        if env[0] == 0x03:
            versioned_hashes += [Bytes32(v) for v in rlp.decode(env[1:])[10]]

    if h(20):
        got = hashlib.sha256(
            b"".join(hashlib.sha256(r).digest() for r in requests)
        ).digest()
        if got != h(20):
            raise ValueError("requests don't match the header requests_hash")
    elif requests:
        raise ValueError("requests present before Prague")
    if h(21):
        if keccak256(bal) != h(21):
            raise ValueError("BAL doesn't match the header block_access_list_hash")
    elif bal:
        raise ValueError("BAL present before Amsterdam")

    payload = ExecutionPayload(
        parent_hash=Bytes32(h(0)),
        fee_recipient=Bytes20(h(2)),
        state_root=Bytes32(h(3)),
        receipts_root=Bytes32(h(5)),
        logs_bloom=Bytes256(h(6)),
        prev_randao=Bytes32(h(13)),
        block_number=Uint(u(h(8))),
        gas_limit=Uint(u(h(9))),
        gas_used=Uint(u(h(10))),
        timestamp=U256(u(h(11))),
        extra_data=Bytes(h(12)),
        base_fee_per_gas=Uint(u(h(15))),
        block_hash=Bytes32(block_hash),
        transactions=tuple(Bytes(e) for e in envelopes),
        withdrawals=tuple(
            Withdrawal(
                index=U64(u(w[0])),
                validator_index=U64(u(w[1])),
                address=Bytes20(w[2]),
                amount=U64(u(w[3])),
            )
            for w in withdrawals
        ),
        blob_gas_used=U64(u(h(17))),
        excess_blob_gas=U64(u(h(18))),
        block_access_list=Bytes(bal),
        slot_number=U64(u(h(22))),
    )
    npr = NewPayloadRequest(
        execution_payload=payload,
        versioned_hashes=tuple(versioned_hashes),
        parent_beacon_block_root=Bytes32(h(19) or b"\0" * 32),
        execution_requests=decode_execution_requests(requests),
    )
    return bytes(block_hash), bytes(npr.hash_tree_root())


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rpc-url", default="http://localhost:8545")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--block", type=int, help="block number, fetched from --rpc-url")
    src.add_argument("--block-rlp", help="hex RLP of the block")
    ap.add_argument("--npr-dump", required=True,
                    help="stderr of the guest run with ZEG_DUMP_NPR=1")
    ap.add_argument("--es-src", default="es-repo/src",
                    help="execution-specs src/ directory")
    args = ap.parse_args()
    sys.path.insert(0, args.es_src)

    if args.block_rlp is not None:
        raw = bytes.fromhex(args.block_rlp.removeprefix("0x"))
    else:
        raw = bytes.fromhex(
            rpc(args.rpc_url, "debug_getRawBlock", [hex(args.block)])[2:]
        )
    requests, bal = read_dump(args.npr_dump)
    try:
        block_hash, root = npr_root(raw, requests, bal)
    except ValueError as e:
        sys.exit(str(e))
    print("0x" + block_hash.hex())
    print("0x" + root.hex())


if __name__ == "__main__":
    main()

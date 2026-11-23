"""
Generate the input-limit killer block: a valid Amsterdam block whose guest input
exceeds ZisK's 2 GiB input region.

On a Merkle-Patricia state an account commits to its code only by hash, so a
stateless guest needs the whole code for every EXTCODESIZE: the size is not
provable otherwise. Amsterdam raises the code limit to 64 KiB (EIP-7954) and a
cold EXTCODESIZE costs 3000 + 100 (EIP-8038) whatever the code size, so about
3.1k gas pulls 64 KiB into the input. A 200M block of cold EXTCODESIZE over
distinct max-size contracts needs about 4.2 GB of input, twice ZisK's
MAX_INPUT_SIZE (2 GiB at INPUT_ADDR). Any block above about 101M gas of this
kind can't be proven.

Layout:
- CONTRACTS contracts of 64 KiB at START + i: STOP, a 4-byte index (every code
  is distinct: the input stores each code once, by hash), then zeros.
- One caller: `PUSH0 CALLDATALOAD` (start address), then a loop of
  `DUP1 EXTCODESIZE POP PUSH1 1 ADD` (unrolled 16x) that runs until out of gas.
- Transactions of up to 2^24 gas (EIP-7825) fill the block gas limit. Each
  one starts where the previous one stopped, so every contract is loaded cold
  once. With fewer contracts than the gas reaches, the remaining transactions
  reload them (no new input) until the gas is spent.

Committed blocks (make killer; generated from this script):
- input_limit_extcodesize_34k_200M.json.xz: `--contracts 34000`, about the
  smallest block sure to fail: a 2,234,400,712-byte input (2.08 GiB).
- large/input_limit_extcodesize_64k_200M.json.xz: `--contracts 0` (the
  default) sizes the set to the gas: 64,206 contracts, a 4,219,490,456-byte
  input (3.93 GiB). Opt-in (KILLER_LARGE=1): phase 1 needs ~9 GB of RAM.

EELS `fill` can't build this block: the fixture's pre- and post-state alone
would be ~17 GB of JSON in memory. This script drives EELS (Amsterdam,
execution-specs tests-zkevm-benchmark@v21.0.5) directly, keeps the codes lazy
(only their hashes are held), executes and validates the block with
`execute_block`, and streams a blockchain_test fixture without a post-state.
Run it with that checkout's environment, memory-capped:

    systemd-run --user --scope -p MemoryMax=6G -q \
        <execution-specs>/.venv/bin/python -I gen_input_limit_block.py \
        --contracts 34000 --out input_limit_extcodesize_34k_200M.json

then `xz -9e` the JSON (gzip is ~8x larger on this much near-identical hex).
"""

import argparse
import json
import sys
import time

from ethereum_rlp import rlp
from ethereum_types.bytes import Bytes, Bytes8, Bytes32
from ethereum_types.numeric import U64, U256, Uint

from ethereum.crypto.hash import keccak256
from ethereum.forks.amsterdam import vm
from ethereum.forks.amsterdam.block_access_lists import (
    BlockAccessListBuilder,
    hash_block_access_list,
)
from ethereum.forks.amsterdam.blocks import Block, Header
from ethereum.forks.amsterdam.bloom import logs_bloom
from ethereum.forks.amsterdam.fork import (
    ChainContext,
    apply_body,
    calculate_base_fee_per_gas,
    execute_block,
)
from ethereum.forks.amsterdam.requests import compute_requests_hash
from ethereum.forks.amsterdam.state_tracker import (
    BlockState,
    extract_block_diff,
)
from ethereum.forks.amsterdam.transactions import (
    LegacyTransaction,
    calculate_intrinsic_cost,
)
from ethereum.forks.amsterdam.vm.gas import calculate_excess_blob_gas
from ethereum.merkle_patricia_trie import EMPTY_TRIE_ROOT, root
from ethereum.state import Account
from ethereum.state_mpt import State, set_account, set_storage, store_code
from execution_testing import TestPrivateKey, Transaction
from execution_testing.forks import Amsterdam

CHAIN_ID = 1
CODE_SIZE = 0x10000  # Amsterdam MAX_CODE_SIZE (EIP-7954)
TX_GAS_CAP = 2**24  # EIP-7825
START = 0x20000000000000000000  # contract i lives at START + i
UNROLL = 16
COINBASE = bytes.fromhex("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba")
CALLER = (0x30000000000000000000).to_bytes(20, "big")
GAS_PRICE = 10

# Opcode gas (Amsterdam): cold account 3000 + code read 100 (EIP-8038).
G_EXTCODESIZE = 3100
G_ITER = 3 + G_EXTCODESIZE + 2 + 3 + 3  # DUP1 EXTCODESIZE POP PUSH1 ADD
G_BLOCK = 1 + 3 + 8  # JUMPDEST, PUSH1 JUMP
G_SETUP = 2 + 3  # PUSH0 CALLDATALOAD

# EEST's blob schedule for an Amsterdam fixture (config.blobSchedule).
BLOB_SCHEDULE = {
    "Cancun": {"target": "0x03", "max": "0x06", "baseFeeUpdateFraction": "0x32f0ed"},
    "Prague": {"target": "0x06", "max": "0x09", "baseFeeUpdateFraction": "0x4c6964"},
    "Osaka": {"target": "0x06", "max": "0x09", "baseFeeUpdateFraction": "0x4c6964"},
    "BPO1": {"target": "0x0a", "max": "0x0f", "baseFeeUpdateFraction": "0x7f5a51"},
    "BPO2": {"target": "0x0e", "max": "0x15", "baseFeeUpdateFraction": "0xb24b3f"},
    "Amsterdam": {"target": "0x0e", "max": "0x15", "baseFeeUpdateFraction": "0xb24b3f"},
}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def contract_code(i: int) -> bytes:
    return b"\x00" + i.to_bytes(4, "big") + bytes(CODE_SIZE - 5)


def contract_address(i: int) -> bytes:
    return (START + i).to_bytes(20, "big")


class LazyCodes(dict):
    """Code store that regenerates the contracts' codes from their hash."""

    def __init__(self, index_of_hash: dict) -> None:
        super().__init__()
        self.index_of_hash = index_of_hash

    def __missing__(self, code_hash):
        return Bytes(contract_code(self.index_of_hash[code_hash]))


def caller_code() -> bytes:
    body = bytes([0x80, 0x3B, 0x50, 0x60, 0x01, 0x01]) * UNROLL
    return bytes([0x5F, 0x35, 0x5B]) + body + bytes([0x60, 0x02, 0x56])


def loads_for(exec_gas: int) -> int:
    """EXTCODESIZE calls the caller completes with `exec_gas`."""
    g = exec_gas - G_SETUP
    n = 0
    while True:
        g -= 1  # JUMPDEST
        for _ in range(UNROLL):
            if g < 3 + G_EXTCODESIZE:
                return n
            g -= G_ITER
            n += 1
        g -= 3 + 8


def sign(nonce: int, gas: int, start: int) -> LegacyTransaction:
    tx = Transaction(
        ty=0,
        to=CALLER,
        gas_limit=gas,
        gas_price=GAS_PRICE,
        nonce=nonce,
        data=(START + start).to_bytes(32, "big"),
        protected=True,
        secret_key=TestPrivateKey,
    ).with_signature_and_sender()
    return rlp.decode_to(LegacyTransaction, bytes(tx.rlp()))


def plan_txs(gas_limit: int, contracts: int):
    """[(gas, start, loads)], and the contract count."""
    gases = []
    left = gas_limit
    while left >= 21_000 + 100_000:
        g = min(TX_GAS_CAP, left)
        gases.append(g)
        left -= g
    # Intrinsic gas of one of these transactions (same calldata shape).
    probe = sign(0, TX_GAS_CAP, 0)
    intr = calculate_intrinsic_cost(probe, probe_sender()).execution
    loads = [loads_for(g - int(intr)) for g in gases]
    if contracts == 0:
        contracts = sum(loads)
    plan, nxt = [], 0
    for g, n in zip(gases, loads):
        if nxt >= contracts:
            nxt = 0
        start = min(nxt, max(contracts - n, 0))
        plan.append((g, start, n))
        nxt = start + n
    return plan, contracts


_SENDER = None


def probe_sender():
    global _SENDER
    if _SENDER is None:
        tx = Transaction(
            ty=0, to=CALLER, gas_limit=21000, protected=True,
            secret_key=TestPrivateKey,
        ).with_signature_and_sender()
        _SENDER = bytes(tx.sender)
    return _SENDER


def hx(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    s = f"{int(v):x}"
    return "0x" + ("0" * (len(s) % 2)) + s


def header_json(h: Header) -> dict:
    return {
        "parentHash": hx(h.parent_hash),
        "uncleHash": hx(h.ommers_hash),
        "coinbase": hx(h.coinbase),
        "stateRoot": hx(h.state_root),
        "transactionsTrie": hx(h.transactions_root),
        "receiptTrie": hx(h.receipt_root),
        "bloom": hx(h.bloom),
        "difficulty": hx(h.difficulty),
        "number": hx(h.number),
        "gasLimit": hx(h.gas_limit),
        "gasUsed": hx(h.gas_used),
        "timestamp": hx(h.timestamp),
        "extraData": hx(h.extra_data),
        "mixHash": hx(h.prev_randao),
        "nonce": hx(h.nonce),
        "baseFeePerGas": hx(h.base_fee_per_gas),
        "withdrawalsRoot": hx(h.withdrawals_root),
        "blobGasUsed": hx(h.blob_gas_used),
        "excessBlobGas": hx(h.excess_blob_gas),
        "parentBeaconBlockRoot": hx(h.parent_beacon_block_root),
        "requestsHash": hx(h.requests_hash),
        "blockAccessListHash": hx(h.block_access_list_hash),
        "slotNumber": hx(h.slot_number),
        "hash": hx(keccak256(rlp.encode(h))),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--contracts", type=int, default=0,
                    help="distinct 64 KiB contracts (0: as many as the gas loads)")
    ap.add_argument("--gas", type=int, default=200_000_000, help="block gas limit")
    ap.add_argument("--out", required=True, help="fixture JSON to write")
    args = ap.parse_args()

    plan, n = plan_txs(args.gas, args.contracts)
    log(f"{len(plan)} transactions, {n} contracts, "
        f"{n * CODE_SIZE / 1e9:.2f} GB of code")

    # Pre-state: EEST's Amsterdam pre-allocation (system contracts), the
    # sender, the caller, and the contracts (codes held lazily, by hash).
    state = State()
    pre_accounts = []  # (address, nonce, balance, code or index, storage)
    for addr, acc in Amsterdam.pre_allocation_blockchain().items():
        a = int(addr).to_bytes(20, "big")
        code = acc.get("code", b"")
        code = bytes.fromhex(code[2:]) if isinstance(code, str) else bytes(code)
        storage = {int(k): int.from_bytes(v, "big") if isinstance(v, bytes)
                   else int(v) for k, v in acc.get("storage", {}).items()}
        pre_accounts.append((a, int(acc.get("nonce", 0)),
                             int(acc.get("balance", 0)), code, storage))
    sender = probe_sender()
    pre_accounts.append((sender, 0, 10**24, b"", {}))
    pre_accounts.append((CALLER, 1, 0, caller_code(), {}))
    for a, nonce, bal, code, storage in pre_accounts:
        ch = store_code(state, Bytes(code))
        set_account(state, a, Account(nonce=Uint(nonce), balance=U256(bal),
                                      code_hash=ch))
        for k, v in storage.items():
            if v:
                set_storage(state, a, k.to_bytes(32, "big"), U256(v))

    index_of_hash = {}
    for i in range(n):
        h = keccak256(contract_code(i))
        index_of_hash[h] = i
        set_account(state, contract_address(i),
                    Account(nonce=Uint(1), balance=U256(0), code_hash=h))
    lazy = LazyCodes(index_of_hash)
    lazy.update(state._code_store)
    state._code_store = lazy
    log("pre-state built")

    pre_root = state.compute_state_root(
        __import__("ethereum.state", fromlist=["BlockDiff"]).BlockDiff())
    log(f"pre state root {hx(pre_root)}")

    empty_list_hash = keccak256(rlp.encode([]))
    genesis = Header(
        parent_hash=Bytes32(bytes(32)),
        ommers_hash=empty_list_hash,
        coinbase=bytes(20),
        state_root=pre_root,
        transactions_root=EMPTY_TRIE_ROOT,
        receipt_root=EMPTY_TRIE_ROOT,
        bloom=bytes(256),
        difficulty=Uint(0),
        number=Uint(0),
        gas_limit=Uint(args.gas),
        gas_used=Uint(0),
        timestamp=U256(0),
        extra_data=Bytes(b"\x00"),
        prev_randao=Bytes32(bytes(32)),
        nonce=Bytes8(bytes(8)),
        base_fee_per_gas=Uint(7),
        withdrawals_root=EMPTY_TRIE_ROOT,
        blob_gas_used=U64(0),
        excess_blob_gas=U64(0),
        parent_beacon_block_root=Bytes32(bytes(32)),
        requests_hash=compute_requests_hash([]),
        block_access_list_hash=empty_list_hash,
        slot_number=U64(0),
    )
    genesis_hash = keccak256(rlp.encode(genesis))

    txs = tuple(sign(k, g, s) for k, (g, s, _) in enumerate(plan))

    def env_for(header_fields) -> vm.BlockEnvironment:
        return vm.BlockEnvironment(
            chain_id=U64(CHAIN_ID),
            state=BlockState(pre_state=state),
            block_gas_limit=Uint(args.gas),
            block_hashes=[genesis_hash],
            coinbase=COINBASE,
            number=Uint(1),
            base_fee_per_gas=header_fields["base_fee"],
            time=U256(12),
            prev_randao=Bytes32(bytes(32)),
            excess_blob_gas=header_fields["excess_blob_gas"],
            parent_beacon_block_root=Bytes32(bytes(32)),
            block_access_list_builder=BlockAccessListBuilder(),
            slot_number=U64(0),
        )

    fields = {
        "base_fee": calculate_base_fee_per_gas(
            Uint(args.gas), genesis.gas_limit, genesis.gas_used,
            genesis.base_fee_per_gas),
        "excess_blob_gas": calculate_excess_blob_gas(genesis),
    }
    env = env_for(fields)
    out = apply_body(block_env=env, transactions=txs, withdrawals=())
    diff = extract_block_diff(env.state)
    post_root = state.compute_state_root(diff)
    log(f"executed: gas {out.block_gas_used}, post state root {hx(post_root)}")

    # Every contract must be in the access list, i.e. loaded.
    touched = {bytes(a.address) for a in out.block_access_list}
    missing = [i for i in range(n) if contract_address(i) not in touched]
    assert not missing, f"{len(missing)} contracts never loaded, e.g. {missing[:5]}"

    header = Header(
        parent_hash=genesis_hash,
        ommers_hash=empty_list_hash,
        coinbase=COINBASE,
        state_root=post_root,
        transactions_root=root(out.transactions_trie),
        receipt_root=root(out.receipts_trie),
        bloom=logs_bloom(out.block_logs),
        difficulty=Uint(0),
        number=Uint(1),
        gas_limit=Uint(args.gas),
        gas_used=max(out.block_gas_used, out.block_state_gas_used),
        timestamp=U256(12),
        extra_data=Bytes(b""),
        prev_randao=Bytes32(bytes(32)),
        nonce=Bytes8(bytes(8)),
        base_fee_per_gas=fields["base_fee"],
        withdrawals_root=root(out.withdrawals_trie),
        blob_gas_used=U64(out.blob_gas_used),
        excess_blob_gas=fields["excess_blob_gas"],
        parent_beacon_block_root=Bytes32(bytes(32)),
        requests_hash=compute_requests_hash(out.requests),
        block_access_list_hash=hash_block_access_list(out.block_access_list),
        slot_number=U64(0),
    )
    block = Block(header=header, transactions=txs, ommers=(), withdrawals=())

    # Independent check: the spec's own block execution accepts the block.
    execute_block(block, state, ChainContext(
        chain_id=U64(CHAIN_ID), block_hashes=[genesis_hash],
        parent_header=genesis))
    block_hash = keccak256(rlp.encode(header))
    log(f"block valid: hash {hx(block_hash)}, gas used {header.gas_used}")

    name = (f"cpp-guest/test/fixtures/killer/gen_input_limit_block.py::"
            f"input_limit_extcodesize[fork_Amsterdam-blockchain_test-"
            f"contracts_{n}-gas_{args.gas // 1_000_000}M]")
    genesis_rlp = rlp.encode(Block(header=genesis, transactions=(), ommers=(),
                                   withdrawals=()))
    with open(args.out, "w") as f:
        f.write("{" + json.dumps(name) + ": {")
        f.write('"network": "Amsterdam", ')
        f.write('"genesisBlockHeader": ' + json.dumps(header_json(genesis)) + ", ")
        f.write('"pre": {')
        first = True

        def account(addr: bytes, nonce: int, bal: int, code_hex: str,
                    storage: dict) -> None:
            nonlocal first
            f.write(("" if first else ", ") + json.dumps(hx(addr)) + ": ")
            first = False
            st = ", ".join(f'"{hx(k)}": "{hx(v)}"' for k, v in storage.items() if v)
            f.write(f'{{"nonce": "{hx(nonce)}", "balance": "{hx(bal)}", '
                    f'"code": "{code_hex}", "storage": {{{st}}}}}')

        for a, nonce, bal, code, storage in pre_accounts:
            account(a, nonce, bal, "0x" + code.hex(), storage)
        for i in range(n):
            account(contract_address(i), 1, 0, "0x" + contract_code(i).hex(), {})
        f.write("}, ")
        f.write(f'"postStateHash": "{hx(post_root)}", ')
        f.write(f'"lastblockhash": "{hx(block_hash)}", ')
        f.write('"config": ' + json.dumps({"network": "Amsterdam",
                                           "chainid": hx(CHAIN_ID),
                                           "blobSchedule": BLOB_SCHEDULE}) + ", ")
        f.write(f'"genesisRLP": "{hx(genesis_rlp)}", ')
        f.write('"blocks": [' + json.dumps({
            "blockHeader": header_json(header),
            "rlp": hx(rlp.encode(block)),
            "blocknumber": "1",
            "uncleHeaders": [],
            "withdrawals": [],
        }) + "], ")
        f.write('"sealEngine": "NoProof", ')
        f.write('"_info": ' + json.dumps({
            "fixture-format": "blockchain_test",
            "comment": "generated by cpp-guest/test/fixtures/killer/"
                       "gen_input_limit_block.py (EELS tests-zkevm-benchmark@v21.0.5)",
            "description": f"{len(txs)} transactions of cold EXTCODESIZE over "
                           f"{n} distinct 64 KiB contracts",
        }))
        f.write("}}\n")
    log(f"wrote {args.out}")


if __name__ == "__main__":
    main()

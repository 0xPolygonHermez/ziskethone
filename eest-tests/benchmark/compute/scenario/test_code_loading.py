"""
Benchmark worst-case *code loading*: a valid block that forces the client (and,
for a stateless/zk verifier, the prover) to bring in and process as many DISTINCT
maximum-size contracts as possible.

Why this is a stress case
--------------------------
A stateless verifier must keccak-hash every contract whose bytecode appears in the
block witness, to check it against the account's ``codeHash``. For a zk prover that
keccak dominates cost (~181 keccak-f permutations per 24 KiB contract), yet the only
gas an attacker pays to pull a contract's code into the witness is the flat EIP-2929
cold-account fee (2600 gas on Prague/Osaka) — there is no per-byte code-access gas
(EIP-7907 is not in these forks). So a 24 KiB contract and a 1-byte contract cost the
attacker the same, and a block can force ~(block_gas / 2600) distinct max-size
contracts to be hashed. Executed (CALLed) contracts are additionally JUMPDEST-analyzed.

This mirrors ``test_unchunkified_bytecode`` but is purpose-built to *maximize the
number of distinct contracts loaded per block*: every transaction cold-touches a
DISJOINT window of never-repeated contracts (via the CREATE2 salt), so the whole
block loads ``sum(iterations)`` distinct contracts with no overlap. Two target ops
are measured:

* ``CALL``        — forces both the hash (code in witness) and the JUMPDEST analysis
                    (the "BigReturnOnly + MultiCall" shape: each target's first byte
                    is a STOP/RETURN stub, so the call returns immediately).
* ``EXTCODESIZE`` — forces only the hash (code must be present to return its length),
                    the cheapest per-gas way to maximize contracts hashed.
"""

from typing import List

import pytest
from execution_testing import (
    Account,
    Alloc,
    BenchmarkTestFiller,
    Block,
    Bytecode,
    Create2PreimageLayout,
    Fork,
    Hash,
    IteratingBytecode,
    Op,
    TestPhaseManager,
    While,
)

from tests.benchmark.helper.contract_factory import (
    ContractDeploymentTransaction,
    CustomSizedContractFactory,
)


@pytest.mark.parametrize(
    "opcode",
    [
        Op.CALL,         # hash + JUMPDEST analyze (BigReturnOnly / MultiCall)
        Op.EXTCODESIZE,  # hash only, cheapest per gas
    ],
)
def test_code_loading(
    benchmark_test: BenchmarkTestFiller,
    pre: Alloc,
    fork: Fork,
    opcode: Op,
    gas_benchmark_value: int,
    fixed_opcode_count: float | None,
) -> None:
    """
    Load as many distinct max-size contracts as the block budget allows, each
    cold-touched exactly once (no repeats across the whole block).
    """
    attack_gas_limit = gas_benchmark_value

    # "BigReturnOnly": max-size, distinct, STOP/RETURN-prefixed contracts. The
    # factory's initcode seeds each body from the contract's own CREATE2 address
    # so every deployed contract has distinct bytes (no code-hash dedup), and its
    # first executed byte is a STOP.
    factory = CustomSizedContractFactory(pre=pre, fork=fork)
    factory_address = factory.address()
    initcode = factory.initcode

    # "MultiCall": a loop that cold-touches a *different* BigReturnOnly contract
    # each iteration. The target address is recomputed from the CREATE2 preimage
    # and the salt is bumped every iteration, so no contract is ever touched twice.
    create2_preimage = Create2PreimageLayout(
        factory_address=factory_address,
        salt=Op.CALLDATALOAD(0),  # per-tx start salt -> disjoint windows
        init_code_hash=initcode.keccak256(),
    )
    setup_code: Bytecode = create2_preimage
    attack_call = Op.POP(
        opcode(
            address=create2_preimage.address_op(),
            address_warm=False,  # cold: forces the code into the witness
        )
    )
    loop_code = While(body=attack_call + create2_preimage.increment_salt_op())
    attack_code = IteratingBytecode(
        setup=setup_code,
        iterating=loop_code,
        # Targets start with STOP, so the per-iteration subcall is a STOP.
        iterating_subcall=Op.STOP,
    )

    # Each transaction advances a disjoint salt window; `start_iteration` is the
    # first salt this tx uses. Passing it as calldata makes the windows
    # non-overlapping across the whole block => every loaded contract is unique.
    def calldata(iteration_count: int, start_iteration: int) -> bytes:
        del iteration_count
        return Hash(start_iteration)

    attack_address = pre.deploy_contract(code=attack_code)

    # Number of distinct contracts to load this block.
    if fixed_opcode_count is not None:
        num_contracts = int(fixed_opcode_count * 1000)
    else:
        num_contracts = sum(
            attack_code.tx_iterations_by_gas_limit(
                fork=fork,
                gas_limit=attack_gas_limit,
                calldata=calldata,
            )
        )

    # Setup block: mass-deploy the distinct max-size contracts via the CREATE2
    # factory (split across txs, each capped by the EIP-7825 tx gas limit).
    post = {}
    with TestPhaseManager.setup():
        setup_sender = pre.fund_eoa()
        deployment_txs: List[ContractDeploymentTransaction] = []
        for tx in factory.transactions_by_total_contract_count(
            fork=fork,
            sender=setup_sender,
            contract_count=num_contracts,
        ):
            deployment_txs.append(tx)
            if factory.contract_size > 0:
                post[tx.deployed_contracts[-1]] = Account(nonce=1)

    # Attack block: one or more txs, each cold-touching a disjoint window of the
    # distinct contracts (sized to the gas budget / per-tx EIP-7825 cap).
    with TestPhaseManager.execution():
        attack_sender = pre.fund_eoa()
        attack_txs = list(
            attack_code.transactions_by_gas_limit(
                fork=fork,
                gas_limit=attack_gas_limit,
                sender=attack_sender,
                to=attack_address,
                calldata=calldata,
            )
        )
        total_gas_cost = sum(tx.gas_cost for tx in attack_txs)

    benchmark_test(
        pre=pre,
        post=post,
        blocks=[
            Block(txs=deployment_txs),  # deploy the distinct max-size contracts
            Block(txs=attack_txs),      # load them all, once each
        ],
        target_opcode=opcode,
        expected_benchmark_gas_used=total_gas_cost,
    )

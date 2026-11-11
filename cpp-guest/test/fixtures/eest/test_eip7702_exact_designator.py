"""
EIP-7702: only exactly `0xef0100 || address` (23 bytes) is a delegation.

Code with the same prefix and any other length is ordinary code that aborts on
the 0xef opcode. New code can't start with 0xef after London (EIP-3541), so this
state can only be pre-London code; the test places it in the pre-state.

Source of the eip7702_exact_designator_*.json fixtures here. Copy it to
execution-specs tests/prague/eip7702_set_code_tx/ and run
`fill --from Osaka --until Amsterdam`.
"""

import pytest
from execution_testing import (
    Account,
    Alloc,
    Block,
    BlockchainTestFiller,
    Bytes,
    Op,
    Transaction,
)

from .spec import Spec, ref_spec_7702

REFERENCE_SPEC_GIT_PATH = ref_spec_7702.git_path
REFERENCE_SPEC_VERSION = ref_spec_7702.version

pytestmark = pytest.mark.valid_from("Osaka")

SLOT = 1
RESULT_SLOT = 0
RESULT_UNSET = 2


def code_of_size(pre: Alloc, size: int) -> Bytes:
    """Return a code of `size` bytes with the delegation prefix."""
    delegate = pre.deploy_contract(code=Op.SSTORE(SLOT, 1) + Op.STOP)
    designation = bytes(Spec.delegation_designation(delegate))
    return Bytes((designation + bytes(size))[:size])


SIZES = pytest.mark.parametrize("size", [3, 22, 23, 24, 64])


@SIZES
def test_top_level(
    pre: Alloc, blockchain_test: BlockchainTestFiller, size: int
) -> None:
    """A transaction sent directly to the account."""
    target = pre.deploy_contract(code=code_of_size(pre, size))
    tx = Transaction(sender=pre.fund_eoa(), to=target, gas_limit=2_000_000)
    storage = {SLOT: 1} if size == 23 else {}
    blockchain_test(
        pre=pre,
        blocks=[Block(txs=[tx])],
        post={target: Account(storage=storage)},
    )


@SIZES
@pytest.mark.parametrize(
    "call",
    [
        pytest.param(Op.CALL, id="call"),
        pytest.param(Op.CALLCODE, id="callcode"),
        pytest.param(Op.DELEGATECALL, id="delegatecall"),
        pytest.param(Op.STATICCALL, id="staticcall"),
    ],
)
def test_nested(
    pre: Alloc, blockchain_test: BlockchainTestFiller, size: int, call: Op
) -> None:
    """A call to the account from a contract."""
    target = pre.deploy_contract(code=code_of_size(pre, size))
    args = (
        (500_000, target, 0, 0, 0, 0, 0)
        if call in (Op.CALL, Op.CALLCODE)
        else (500_000, target, 0, 0, 0, 0)
    )
    caller = pre.deploy_contract(
        code=Op.SSTORE(RESULT_SLOT, call(*args)) + Op.STOP,
        storage={RESULT_SLOT: RESULT_UNSET},
    )
    tx = Transaction(sender=pre.fund_eoa(), to=caller, gas_limit=2_000_000)

    delegated = size == 23
    # A delegated STATICCALL runs the delegate and fails on its SSTORE.
    success = delegated and call != Op.STATICCALL
    writes_caller = success and call in (Op.CALLCODE, Op.DELEGATECALL)
    writes_target = success and call == Op.CALL

    caller_storage = {RESULT_SLOT: 1 if success else 0}
    if writes_caller:
        caller_storage[SLOT] = 1
    blockchain_test(
        pre=pre,
        blocks=[Block(txs=[tx])],
        post={
            caller: Account(storage=caller_storage),
            target: Account(storage={SLOT: 1} if writes_target else {}),
        },
    )

"""
EIP-7928: the account load paid for by EXTCODECOPY, whatever the copy size.

The spec charges the opcode's gas and then reads the account, so the account
is in the block access list even with size 0, and even if a later opcode in the
same frame halts exceptionally. Only a failed charge leaves it out.

Source of the bal_extcodecopy_*.json fixtures here. Copy it to execution-specs
tests/amsterdam/eip7928_block_level_access_lists/ and run `fill --fork Amsterdam`.
"""

import pytest
from execution_testing import (
    AccessList,
    Address,
    Alloc,
    BalAccountExpectation,
    BalNonceChange,
    Block,
    BlockAccessListExpectation,
    BlockchainTestFiller,
    Bytecode,
    Op,
    Transaction,
)

from .spec import ref_spec_7928

REFERENCE_SPEC_GIT_PATH = ref_spec_7928.git_path
REFERENCE_SPEC_VERSION = ref_spec_7928.version

pytestmark = pytest.mark.valid_from("Amsterdam")

MISSING_ACCOUNT = Address(0x7777777777777777777777777777777777777777)


def run(
    pre: Alloc,
    blockchain_test: BlockchainTestFiller,
    target: Address,
    code: Bytecode,
    access_list: list[AccessList] | None = None,
) -> None:
    """Run `code` in one transaction and expect `target` in the BAL."""
    alice = pre.fund_eoa()
    contract = pre.deploy_contract(code=code)
    tx = Transaction(sender=alice, to=contract, access_list=access_list)
    block = Block(
        txs=[tx],
        expected_block_access_list=BlockAccessListExpectation(
            account_expectations={
                alice: BalAccountExpectation(
                    nonce_changes=[
                        BalNonceChange(block_access_index=1, post_nonce=1)
                    ]
                ),
                target: BalAccountExpectation.empty(),
                contract: BalAccountExpectation.empty(),
            }
        ),
    )
    blockchain_test(pre=pre, blocks=[block], post={})


@pytest.mark.parametrize("size", [0, 32], ids=["size0", "size32"])
@pytest.mark.parametrize(
    "tail",
    [
        pytest.param(Op.INVALID, id="invalid"),
        pytest.param(Op.REVERT(0, 0), id="revert"),
        pytest.param(Op.STOP, id="stop"),
        pytest.param(Op.POP, id="underflow"),
        pytest.param(Op.SHA3(0, 0x10000000000), id="later_oog"),
    ],
)
def test_bal_extcodecopy_then_halt(
    pre: Alloc,
    blockchain_test: BlockchainTestFiller,
    size: int,
    tail: Bytecode,
) -> None:
    """The load survives whatever ends the frame."""
    target = pre.deploy_contract(code=Op.STOP)
    run(pre, blockchain_test, target, Op.EXTCODECOPY(target, 0, 0, size) + tail)


def test_bal_extcodecopy_zero_warm_by_access_list(
    pre: Alloc, blockchain_test: BlockchainTestFiller
) -> None:
    """An access-list warm address has no cold charge, and is still loaded."""
    target = pre.deploy_contract(code=Op.STOP)
    run(
        pre,
        blockchain_test,
        target,
        Op.EXTCODECOPY(target, 0, 0, 0) + Op.INVALID,
        access_list=[AccessList(address=target, storage_keys=[])],
    )


def test_bal_extcodecopy_zero_missing_account(
    pre: Alloc, blockchain_test: BlockchainTestFiller
) -> None:
    """A load of an account that doesn't exist is a load."""
    run(
        pre,
        blockchain_test,
        MISSING_ACCOUNT,
        Op.EXTCODECOPY(MISSING_ACCOUNT, 0, 0, 0) + Op.INVALID,
    )


def test_bal_extcodecopy_zero_cold_charge_oog(
    pre: Alloc, blockchain_test: BlockchainTestFiller
) -> None:
    """A frame that can't pay the cold charge doesn't load the account."""
    alice = pre.fund_eoa()
    target = pre.deploy_contract(code=Op.STOP)
    callee = pre.deploy_contract(code=Op.EXTCODECOPY(target, 0, 0, 0))
    caller = pre.deploy_contract(code=Op.CALL(1000, callee, 0, 0, 0, 0, 0))
    tx = Transaction(sender=alice, to=caller)
    block = Block(
        txs=[tx],
        expected_block_access_list=BlockAccessListExpectation(
            account_expectations={
                alice: BalAccountExpectation(
                    nonce_changes=[
                        BalNonceChange(block_access_index=1, post_nonce=1)
                    ]
                ),
                caller: BalAccountExpectation.empty(),
                callee: BalAccountExpectation.empty(),
                target: None,
            }
        ),
    )
    blockchain_test(pre=pre, blocks=[block], post={})

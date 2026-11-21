"""
Audit Z-3: thrash the guest's JUMPDEST-analysis cache with warm calls.

The guest keeps code analyses in a fixed LRU cache of ZEG_ANALYSIS_CACHE_SLOTS
(1152) slots (cpp-guest/src/zisk_state_db.cpp). Calling N > 1152 distinct
max-size contracts in a cycle makes every call miss, so every warm CALL (about
100 gas) re-analyses a full-size code: a JUMPDEST bitmap precompile over the
code plus the padded code copy into the slot. In steps the block looks
ordinary; in ZisK cost (`ziskemu -X`) it is several times the costliest
zkevm-benchmark block. If the slot count changes, keep NUM_CONTRACTS above it.

Layout:
- NUM_CONTRACTS contracts of fork.max_code_size() bytes at fixed addresses.
  Each starts with STOP (so the 0-gas frame succeeds at once) and a 4-byte
  index (so every code is distinct), then JUMPDEST filler.
- One caller: JUMPDEST, one unrolled pass of
  `PUSH0 x5, PUSH20 addr, PUSH0, CALL, POP` (about 117 gas per call) over all
  contracts, then `PUSH0 JUMP` back to the start. It runs until out of gas.
- benchmark_test splits the gas into transactions at the per-transaction cap
  (2^24), so a 200M block holds twelve transactions.

Source of zeg_analysis_cache_thrash_amsterdam_200M.json.gz here. To refill it,
in execution-specs at tests-zkevm-benchmark@v21.0.5 with
eels-fill-speedup.patch applied (filler speed only), copy this file to
tests/benchmark/compute/zeg/ (with an empty __init__.py) and run, one worker,
memory-capped:

    systemd-run --user --scope -p MemoryMax=4G -q uv run fill \
        tests/benchmark/compute/zeg/test_zeg_analysis_cache_thrash.py \
        --fork Amsterdam --gas-benchmark-values 200 -k "blockchain_test-" \
        --output <dir> --clean

then `gzip -9n` the produced blockchain_tests JSON.
"""

import pytest
from execution_testing import (
    Address,
    Alloc,
    BenchmarkTestFiller,
    Bytecode,
    Fork,
    Op,
    Transaction,
)

NUM_CONTRACTS = 1153  # > ZEG_ANALYSIS_CACHE_SLOTS (1152): every call misses
START = 0x10000000000000000000  # contract i lives at START + i


@pytest.mark.pre_alloc_mutable
def test_zeg_analysis_cache_thrash(
    benchmark_test: BenchmarkTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """Warm-call NUM_CONTRACTS max-size contracts cyclically, 0 gas each."""
    size = fork.max_code_size()
    filler = b"\x5b" * size
    for i in range(NUM_CONTRACTS):
        code = b"\x00" + i.to_bytes(4, "big") + filler
        pre.deploy_contract(address=Address(START + i), code=code[:size])

    one_pass = Bytecode()
    for i in range(NUM_CONTRACTS):
        one_pass += (
            Op.PUSH0 * 5  # retSize retOff argsSize argsOff value
            + Op.PUSH20(START + i)
            + Op.PUSH0  # gas
            + Op.CALL
            + Op.POP
        )
    caller_code = Op.JUMPDEST + one_pass + Op.PUSH0 + Op.JUMP
    assert len(caller_code) <= size
    caller = pre.deploy_contract(code=caller_code)

    benchmark_test(
        target_opcode=Op.CALL,
        skip_gas_used_validation=True,
        tx=Transaction(to=caller, sender=pre.fund_eoa()),
    )

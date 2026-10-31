# Guest heap budget

The ZisK guest must finish **every** valid block the live prover is handed, so it
must never run out of memory on one. [GLAMSTERDAM.md](GLAMSTERDAM.md) records the
adversarial-but-valid blocks that once exhausted it and the fixes. This file turns
"it has enough memory" from a set of measurements into an argument: for every
allocation site, how much heap a block can make it hold, composed into a
worst-case total per backend and checked against the ELF's heap.

It is enforced, not just written down:

- `make heap-gate` (scripts/heap_gate.py) runs a fixed set of the heaviest killer
  blocks on a heap-stats ELF and fails if any block's heap or arena use regresses
  past its baseline, past the bound below, or past a hard share (60%) of the ELF
  heap. Run it on both backends before deploying (see AGENTS.md).
- `scripts/heap_bound.py` computes the bound from the site table below and checks
  it fits; it also checks this document's table, the tagged `static_assert`s, and
  the citations are current.
- `static_assert`s tagged `// heap-budget: <id>` pin the per-node sizes the model
  relies on, so a layout change forces this file and the table to be updated.

## The allocator

512 MiB of RAM, minus a 4 MiB stack and small reserved regions, leaves the heap
(`cpp-guest/zisk/zisk.ld`, `_heap_start.._heap_end`):

| Backend | Heap |
|---|---|
| evmone | 427.4 MB |
| zevm | 259.3 MB |

Two allocators share it (`cpp-guest/zisk/runtime.cpp`):

- a **bump allocator that never frees**, growing up from `_heap_start`. `free` and
  `delete` are no-ops, so what matters is the total bytes ever handed out, not the
  live set. A `std::vector` that doubles leaves every outgrown buffer behind, which
  is why growing data uses `zeg::ChunkedVector` or an exact `reserve` instead.
- a **per-transaction arena** growing down from `_heap_end`, reset at the start of
  each transaction and system call (`ZiskStateDB::reset_tx_arena`). The journal,
  transient storage, evmone's EVM memory and CREATE-analysis scratch live here, so
  their cost is one transaction's peak, not the block's sum.

They meet in the middle; out of memory is when they would cross.

**Static `.bss` is not in the heap.** The keccak-f memo (100 MiB) and, on zevm, the
128 MiB EVM-memory zones and 33 MiB frame stacks live below `_heap_start`, so they
do not count against the heap figures above and are not budget terms.

## The model

```
required(block) = fixed                      # never-reset reservations
                + txs * per_tx               # ~3 KB of parse/receipt/output state per tx
                + gas * max(gas_rate_i)      # the costliest per-gas heap consumer
                + arena                      # the largest single-transaction arena peak
required(block) <= heap
```

`gas` is the gas that can grow the heap: **regular** gas under Amsterdam (EIP-8037
state gas is refunded and cannot pay for heap), block gas before it; Osaka refunds
let spent gas reach 1.25x `gasUsed`. The per-gas consumers are a **max**, not a
sum: a gas unit is spent once, so the heap it can create is bounded by the single
costliest way to spend it — a cold key (~2100 gas → ~1.2 KB of witness rows, the
dominant 0.6 B/gas), above surviving logs and warm-key revert churn.

Input size is **not** an independent term. Witness nodes and codes are viewed in
the input region, not copied; the heap rows indexing them exist only for state the
block **touched**, which costs cold-access gas — already inside the gas term. A
block whose witness exceeds the 2 GiB input region simply fails to load: that is
the **S3 input-region ceiling**, an operator-side limit (a larger region or input
metering), tracked in [GLAMSTERDAM.md](GLAMSTERDAM.md), not a guest heap bound.

## Allocation sites

Machine-readable in `scripts/heap_gate/sites.tsv`; `scripts/heap_bound.py` reads it
and `--check-doc` keeps the table below in sync. `fixed`/`tx`/`arena` rows sum per
backend; `gas` rows are taken as a max.

<!-- sites:begin -->
| backend | site | lifetime | resource | bytes/unit | source |
|---|---|---|---|---:|---|
| evmone | `analysis_cache` | heap | fixed | 85072992 | evmc2_evmone.cpp:kSlotBytes(73808)*1152 + analysis_cache.hpp:50-51 |
| evmone | `vm_state_vector` | heap | fixed | 467400 | evmone vm.cpp:79 reserve(1025)*sizeof(ExecutionState) |
| evmone | `call_stacks` | heap | fixed | 33587200 | evmone execution_state.hpp:51 32KiB/depth, <=1025 depths |
| zevm | `analysis_cache` | heap | fixed | 9483360 | zevm.cpp:413 slot(8192)*1152 + analysis_cache.hpp:50-51 |
| both | `cold_key_witness` | heap | gas | 0.60 | state_root.cpp + accounts.cpp/storages.cpp: ~1.2KB per cold key / 2100 gas |
| both | `surviving_logs` | heap | gas | 0.375 | zisk_state_db.cpp:647-655 receipt.hpp logs; 375+8/byte gas |
| both | `warmkey_revert_churn` | heap | gas | 0.30 | warm_keys.hpp erase-on-rollback dead nodes, ~250 gas/cycle |
| both | `per_tx_overhead` | heap | tx | 3200 | parse 1.1K + receipts-trie 0.8K + header/NPR 0.5K + exec 0.6K per tx |
| evmone | `tx_arena_peak` | arena | arena | 70000000 | evmc2_evmone.cpp memory views + FrameScratch; recursive-memory tx |
| zevm | `tx_arena_peak` | arena | arena | 40000000 | journal + transient map in the arena (zevm EVM memory is static .bss) |
<!-- sites:end -->

The per-node sizes behind these rows are pinned by `static_assert`s tagged
`// heap-budget: <id>` (`zeg/receipt.hpp`, `zeg/trie_node.hpp`, `zeg/journal.hpp`,
`zeg/accounts.hpp`, `zeg/storages.hpp`, `src/evmc2_evmone.cpp`, `src/zevm/zevm.cpp`).

## Result

At each chain's worst case (the full gas limit spent at the max per-gas rate, plus
as many minimum-gas transactions as the limit allows — both counted, though they
cannot peak together, so this is a loose upper bound):

| Chain (fork) | evmone required / heap | zevm required / heap |
|---|---|---|
| sepolia (Amsterdam, 200M gas) | 362 MB / 427 MB | 223 MB / 259 MB |
| mainnet (Osaka, 60M gas) | 243 MB / 427 MB | 104 MB / 259 MB |

Both fit, with the smaller margin on zevm's Amsterdam case (~36 MB). The bound is a
deliberate over-estimate: `heap_bound.py --check` over a heap-stats run of the
killer suite finds the heaviest block at 0.50 of its own-fork bound on evmone and
0.45 on zevm, so no real block comes near the ceiling. The heap gate records the
worst measured/bound ratio on every run.

> The per-gas and arena rates are a first, deliberately conservative pass
> (an over-estimate only weakens the bound, never hides a failure). They are
> validated to exceed every measured killer block by `heap_bound.py --check`
> against the full heap-stats run; tighter per-site derivations refine them in
> place in `sites.tsv`.

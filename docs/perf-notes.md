# Guest performance notes

Where the ZisK guest spends its budget, what has been done about it, what was
tried and did not pay, and how any of it was measured. Numbers are from block
25701329 unless stated otherwise, on the `perf/dma-precompiles` branch.

**Read the second column.** `area` is what proving pays; steps are a proxy that
sometimes disagrees. The `-mzisk-dma` flag is the clearest example: -14.5% steps
but only -4.96% area, because it trades cheap instructions (MAIN, 68 each) for
DMA operations that bring their own memory cost.

## Where the budget goes

Of block 25701329's 44.6G area, 20.8G is the keccak precompile — a fixed price
we do not control. The **24.5G that is left** breaks down as:

| | area | of what we can touch |
|---|---|---|
| MAIN (steps × 68) | 16.5G | **67%** |
| MEMORY | 4.2G | 17% |
| OPCODES (state machines) | 3.5G | 14% |

So two thirds of the addressable cost is plain instruction count.

### Self steps by function (evmone, 234.8M total)

Inclusive costs are useless for the interpreter — it is recursive, so its number
carries the whole nested call. These are **self** steps, from the PC histogram.

| function | steps | % | owner |
|---|---|---|---|
| `dispatch_cgoto` (the loop itself) | 37,258,448 | 15.9% | evmone |
| `check_requirements` (gas + stack, per opcode) | 17,666,939 | 7.5% | evmone |
| `ethash_keccak256` (the sponge, not the permutation) | 16,622,680 | 7.1% | **ours** |
| `build_branch_node` | 11,722,425 | 5.0% | **ours** |
| SWAP | 8,207,474 | 3.5% | evmone |
| `reduce_branch` | 7,860,599 | 3.3% | **ours** |
| `eval_node` | 6,297,579 | 2.7% | **ours** |
| PUSH (body) | 5,258,524 | 2.2% | evmone |
| `pack_branch` | 4,724,429 | 2.0% | **ours** |
| `pack_key_hash` | 2,599,223 | 1.1% | **ours** |

The MPT (build_branch_node + reduce_branch + eval_node + pack_branch +
pack_key_hash and friends) is the largest thing we own outright.

## The eight blocks

Totals across `data_20260808`, all 32 runs hash-verified against the hash prefix
in each input's filename.

| build | steps | area |
|---|---|---|
| evmone | 1,676,971,663 | 296,357,030,329 |
| **evmone + `-mzisk-dma`** | **1,433,274,221** | **281,652,175,341** |
| zevm | 1,889,678,694 | 320,827,445,006 |
| zevm + `-mzisk-dma` | 1,579,912,702 | 300,588,759,968 |

`-mzisk-dma` is worth -14.5% steps / -4.96% area on evmone and -16.4% / -6.31%
on zevm. zevm sits at +10.2% steps / +6.7% area behind evmone; it was +33% /
+12.6% before the jump-table fix.

Block 25708403 is the outlier at -25.5% steps from the flag against the -13%
typical — it does the most block copying, so it is the one to use when showing
what the lowering does.

## Open, with sizes

Ordered by measured size, not by how interesting they are.

1. **Narrow memory accesses, ~1.41G area (34.9% of MEMORY, 3.2% of the block).**
   The one item here measured in *area*, not steps: it removes no instructions,
   it makes the ones we already run cheaper. On ZisK a memory access gets *more*
   expensive as it gets narrower — an aligned 8B read/write costs 16/18, a 4B
   read 122, a 1B read 41, a 1B clean write 66 and a 1B dirty write 193 — which
   inverts every real CPU, where a `sw` is never worse than a `sd`. Per block:
   18.4M sub-8-byte accesses over 1,769 PCs; at 8 bytes wide they would cost
   ~312M, so ~1.10G (2.5% of the block) is the ceiling. Where they are, from the
   full PC histogram attributed with addr2line:

   | | narrow accesses | |
   |---|---|---|
   | `dispatch_cgoto` | 5,250,013 | evmone, bytecode a byte at a time |
   | MPT (`reduce_branch`, `build_branch_node`, `eval_node`, `pack_*`) | 5,409,978 | **ours** |
   | `std::variant` machinery (`index`, `aux_emplace`, `_M_reset`, ctors) | 3,412,173 | **ours**, the 1-byte discriminant |
   | `load_partial_push_data<1>` | 624,724 | evmone |

   So this is a **data representation** problem, not a compiler one: the traffic
   is on user data structures, not on compiler-chosen stack slots. Two
   independent measurements agree — sweeping `-mmemory-cost` moved nothing (see
   below), and only 1.09M of the 18.4M accesses are `sp`-relative. A
   `-mzisk-wide-stack` patch (8-byte stack slots, DImode spills) was the first
   idea here and the attribution killed it. The `std::variant` row is item 4 seen
   from the memory side. The compiler-shaped part was chased and is closed: only
   512k of the 4.2M narrow stores sit in a run of >= 2 stores inside one 8-byte
   word, worth **151M (0.34%)** if merged, and GCC will not merge them — the
   hot shape is `sb` at offset 0 plus `sw` at offset 4 with dead padding
   between, and store-merging refuses to write bytes the program did not write
   (no `--param` changes it, verified). Merging while *preserving* the padding
   needs `ld`+`and`+`or`+`sd` = 426, worse than the 395 it replaces, so only the
   padding-destroying `sd` (86) pays and that needs a deadness proof. Not worth
   a pass rewrite for 0.34%. Two source-side leads found while looking, both
   bigger: `reduce_branch` advances its output by **33 bytes per child**, so
   every store and every DMA copy in that loop is unaligned by construction and
   pays the pre/post path (91) instead of the 64-bit-aligned one; and 4-byte
   accesses alone cost ~527M (1.18% of the block) at 122/193 against 16/18,
   which is `int`/`uint32_t` fields in hot structures.
2. **`dma_xor`, ~11.5M steps (4.9%).** The keccak sponge absorbs by XORing 8-byte
   lanes into the state: `ld` + `ld` + `xor` + `sd` per lane, 69% of the
   function. A DMA-shaped op — `csrs 0x81X, src` + `add x0, dst, count`, meaning
   `dst[i] ^= src[i]` — collapses a 136-byte block from 17 lanes to one
   operation. Needs a new op in zisk. Measured alignment on this block: the
   destination (the sponge state) is always 8-aligned and the source is aligned
   in 89.6% of calls, the rest at offset 1 (an RLP header in front of the
   payload), so a fast path plus the existing pre/post machinery covers it.
3. **evmone's advanced interpreter, up to 17.7M (7.5%).** `check_requirements`
   runs three compares before every opcode — stack overflow, stack underflow,
   gas — and there is nothing to shave inside it. evmone's `advanced` mode
   precomputes gas and stack requirements per basic block and checks once per
   block; its code is already compiled into our ELF, we simply instantiate the
   baseline VM. It trades an analysis pass per contract, which we already do for
   the JUMPDEST bitmap. Untested.
4. **`variant`/`vector` machinery, 10.9M (4.5%).** `NodeR` is a six-alternative
   `std::variant`; every `holds_alternative`, `get_if` and `visit` checks the
   index, and `reduce_branch` does it 16 times per branch. An enum plus an
   explicit union, or just ordering the frequent case first as `emit_child_slot`
   already does.
5. **Hash lookups, ~11.5M (4.9%).** All `unordered_map`, no binary search:
   Storages, Accounts (20-byte key), DynamicStorage, Journal, Contracts. The keys
   are already high-entropy so hashing is free; the cost is building the key,
   taking the bucket modulo (a `remu`, 97 area vs 25 for an `add`), walking the
   chain and comparing the whole key.

   The *duplicate*-probe half of this is now fixed (see below). What is left, in
   order: keep the 64-bit hash next to the index so the chain walk rejects on 8
   bytes instead of 56; open addressing, to drop the dependent `next` load;
   heterogeneous lookup, so `Storages` stops materialising a 56-byte `Key` on the
   stack for every probe (~6 of the ~22 steps a probe costs).
6. **The SLOAD/SSTORE host round trip, ~1.5M (0.6%).** After the fix below, a
   warm SLOAD still costs 359 steps: 78 in `sload` itself, then *two* full C-ABI
   crossings — `access_storage` then `get_storage` — each re-marshalling the same
   20-byte address and 32-byte key and each probing the map once. The real work,
   one hashmap lookup and a 32-byte read, is under 60 of those steps. Collapsing
   it means a fused host method, which means extending `evmc_host_interface`; we
   own both sides (evmone is patched, `ZiskStateDB` implements `evmc::Host`), so
   it is possible, just invasive. `sload` alone is 2.3% of the block's steps.
6. **SWAP, 8.2M (3.5%).** `swap<1>` alone is 4.3M: two `uint256` through a
   temporary, 12 loads and 12 stores.
7. **`pack_branch`, 4.7M (2.0%).** Writes 17 slots per branch; empty children are
   a single `0x80` byte and are the majority, and `build_branch_node` already
   knows which they are from the tag word — the same trick applied to the `Child`
   array would apply here.
8. **`pack_key_hash`, 2.6M (1.1%).** Still packs the walked path a nibble at a
   time because `WalkPath` is one nibble per byte. Packing it too would make this
   a copy.
9. **Nibble expand/compress ops, ~3.3M.** With `PackedPath` most of the nibble
   traffic is gone; what is left would want an op that expands 32 bits into 8
   nibble-per-byte lanes and its inverse. Lower priority now than it was.

## Done

* **One hashmap probe per storage access instead of two** (-0.60% steps, -0.41%
  area over the eight blocks). `ZiskStateDB`'s three storage entry points each
  asked `Storages` the same question twice — `contains(addr, key)` to branch,
  then `index_of(addr, key)` (or `value(addr, key, tx)`, which calls `index_of`)
  to act — and every one of those is a full probe: build a 56-byte `Key` on the
  stack, hash, `remu`, walk the chain, compare 56 bytes. A warm SLOAD did four of
  them for one slot. `Storages::find` answers both questions in one probe by
  returning `npos`, and the call sites branch on the index.

  Found by disassembling `sload` and following its callees, not by reading the
  source — from C++ the double question looks like two cheap predicates.

## Tried, did not pay

Keeping these so nobody spends the afternoon twice.

* **Routing every explicit `mem*` call through the precompile** (`-fno-builtin-mem*`,
  so they all reach the ziskos thunk): **+29% steps, +13% area**. GCC inlines ~6.9M
  copies per block that are better inline — 78.6% of all copies are <= 8 bytes,
  where `ld`+`sd` beats any marker. This is why `-mzisk-dma` keeps a 16-byte floor.
* **Intercepting `memcpy` from C++** (`extern inline gnu_inline` + `-include`):
  -0.5% steps only. It cannot see the copies GCC generates itself from struct
  assignment, which are the bulk — 1.5M `evmc::bytes32` copies per block. That is
  what pushed the work into the GCC backend instead.
* **Precise memory operands instead of a `"memory"` clobber** in the inline
  markers: no difference (212.15M vs 212.25M). The clobber was not the problem.
* **`-fno-builtin-mem*` on its own**: free. It costs nothing, so it was not what
  made the interception look bad.
* **Constant memset fill in SAR**: -173k steps, not the -5M hoped. SAR's 79
  steps/call live in the limb path (`ld_le` + `shr` + `shl` + 4 ORs + `st_le`),
  not in the fill.
* **`dma_inputcpy` for fcall results**: -31k steps, -2.5M area. Real but small,
  and it scales with the block's signature traffic.
* **`-mstrict-align`**, to stop GCC emitting accesses it cannot prove aligned:
  **+29.7% steps, +17.1% area**, and MEMORY itself went *up* 34.5% (4.08G ->
  5.48G). GCC does not know an access lands aligned at run time, so it splits it
  into byte sequences — static `lbu` 4,398 -> 11,029, static `sb` 1,713 -> 5,955
  — and a byte read costs 41 where the aligned 8-byte read it replaced costs 16.
  The premise was wrong anyway: `--mem-full-stats` puts genuinely misaligned
  traffic (the classes that cross an 8-byte boundary) at ~522k accesses and
  ~110M area, **0.25% of the block**. `slow_unaligned_access = false` is the
  correct setting for us and the alignment axis is closed. What that measurement
  did find is a different thing — narrow accesses. On the stack a 4-byte read
  costs 122 and a 1-byte dirty write 193, against 16/18 for an aligned 8-byte
  access, so here *narrower is more expensive*, the opposite of every real CPU.
  Stack traffic below 8 bytes is 7.29M accesses for 843M area; at 8 bytes it
  would be 123M. See `-mzisk-wide-stack` in the open list.
* **Sweeping `-mmemory-cost=`** (the knob `0002-riscv-zisk-memory-cost.patch`
  adds, so IRA's spill price and the `MEM` case of `riscv_rtx_costs` can be set
  from the command line): nothing there. 1 -> +0.25% steps / +0.14% area; 3 ->
  -0.11% / **-0.05%**; 5 and 8 flat. `-mmemory-cost=2` comes out byte-identical
  to no flag, which is the right sanity check — 2 is the tune default under
  `-mtune=size`. The direction was as predicted (undercharging memory makes GCC
  spill more, and a spilled 32-bit pseudo really does cost 193/122 rather than
  the 86/84 of an 8-byte slot) but the magnitude is noise. The useful negative
  is what it says about the narrow stack traffic above: it is **not** IRA-elective
  spilling, because moving the spill price 4x did not move it. It is slots that
  have to exist — address-taken locals, aggregate temporaries, ABI — which is
  the harder half of `-mzisk-wide-stack`, not the free half.

## How to measure

The emulator to use is **zisk18's or zisk24's, never the `zisk` symlink** — that
one is zisk22 and has no EVM precompiles, so it silently produces a wrong hash.
zisk24's symbol-based profiler panics on our ROM (`stats.rs:2061`,
`external_ref_addr.unwrap()`); zisk18's works.

```bash
cd ../zisk18
# totals + op table
target/release/ziskemu -e ../ziskethone/cpp-guest/zisk/build-dma/zisk_eth_guest.elf \
    -i ../data_20260808/25701329_7b72c0.bin -X

# per function, inclusive; -T sets how many rows
target/release/ziskemu ... -X -S -T 250

# per PC, which is what gives SELF cost and works through inlining
target/release/ziskemu ... -X -H 400000
```

Two traps in reading the report: there are **two `TOTAL` lines** (the op table's
and COST DISTRIBUTION's) and they are different numbers — compare like with like;
and `-S` costs are **inclusive**, so a recursive function like the interpreter
cannot be compared across backends that way.

For self cost through inlined code, attribute PCs to symbols yourself:

```bash
# same flags plus -g; debug sections do not move .text, so the histogram matches
cmake -S cpp-guest/zisk -B build-g ... -DZEG_GUEST_OPT="$OPT -g"
riscv-none-elf-addr2line -e build-g/zisk_eth_guest.elf -f -C @pcs.txt
```

That is how `pack_branch`, `emit_child_slot` and the rest of the RLP encoder were
found: they have no symbols of their own.

### Verifying a change

The block hash is the check, and it is a strong one — every one of these changes
is in the path of every hash in the block. The input filenames carry the
canonical hash prefix (`25701329_7b72c0.bin` -> `0x7b72c0d9…`), so correctness
can be checked without the RPC. **Build the host first**: it runs the same
pipeline in seconds instead of the emulator's minutes, and it caught the one bug
this refactor introduced.

```bash
cmake --build cpp-guest/build -j --target zisk_eth_guest
./cpp-guest/build/zisk_eth_guest <container>.bin [expected-hash]
```

Nothing downstream compares the hash today, in the client or after proving — so
a wrong one only shows up if someone looks.

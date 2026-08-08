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

1. **`dma_xor`, ~11.5M steps (4.9%).** The keccak sponge absorbs by XORing 8-byte
   lanes into the state: `ld` + `ld` + `xor` + `sd` per lane, 69% of the
   function. A DMA-shaped op — `csrs 0x81X, src` + `add x0, dst, count`, meaning
   `dst[i] ^= src[i]` — collapses a 136-byte block from 17 lanes to one
   operation. Needs a new op in zisk. Measured alignment on this block: the
   destination (the sponge state) is always 8-aligned and the source is aligned
   in 89.6% of calls, the rest at offset 1 (an RLP header in front of the
   payload), so a fast path plus the existing pre/post machinery covers it.
2. **evmone's advanced interpreter, up to 17.7M (7.5%).** `check_requirements`
   runs three compares before every opcode — stack overflow, stack underflow,
   gas — and there is nothing to shave inside it. evmone's `advanced` mode
   precomputes gas and stack requirements per basic block and checks once per
   block; its code is already compiled into our ELF, we simply instantiate the
   baseline VM. It trades an analysis pass per contract, which we already do for
   the JUMPDEST bitmap. Untested.
3. **`variant`/`vector` machinery, 10.9M (4.5%).** `NodeR` is a six-alternative
   `std::variant`; every `holds_alternative`, `get_if` and `visit` checks the
   index, and `reduce_branch` does it 16 times per branch. An enum plus an
   explicit union, or just ordering the frequent case first as `emit_child_slot`
   already does.
4. **Hash lookups, 12.9M (5.3%).** All `unordered_map`, no binary search:
   Storages 5.5M (56-byte key), Accounts 2.9M (20 bytes), DynamicStorage 1.8M,
   Journal 1.7M, Contracts 1.0M. The keys are already high-entropy so hashing is
   free; the cost is walking the chained bucket and comparing the whole key. Two
   ideas: keep the 64-bit hash next to the index and reject on 8 bytes instead of
   56, and open addressing to drop the dependent `next` load.
5. **SWAP, 8.2M (3.5%).** `swap<1>` alone is 4.3M: two `uint256` through a
   temporary, 12 loads and 12 stores.
6. **`pack_branch`, 4.7M (2.0%).** Writes 17 slots per branch; empty children are
   a single `0x80` byte and are the majority, and `build_branch_node` already
   knows which they are from the tag word — the same trick applied to the `Child`
   array would apply here.
7. **`pack_key_hash`, 2.6M (1.1%).** Still packs the walked path a nibble at a
   time because `WalkPath` is one nibble per byte. Packing it too would make this
   a copy.
8. **Nibble expand/compress ops, ~3.3M.** With `PackedPath` most of the nibble
   traffic is gone; what is left would want an op that expands 32 bits into 8
   nibble-per-byte lanes and its inverse. Lower priority now than it was.

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

# ZisK DMA lowering for GCC

`0001-riscv-zisk-dma-lowering.patch` teaches the GCC 14.3.0 RISC-V backend to
lower block memory operations to the ZisK DMA precompile markers, instead of
calling the `ziskos` mem\* thunks. It is the GCC counterpart of the LLVM patch in
the Rust fork (`src/llvm-patches/0001-riscv-zisk-dma-lowering.patch`), which
rustc gets through the `+zisk-dma` target feature.

Opt-in through `-mzisk-dma`: without the flag the compiler is byte-for-byte the
stock one (verified — the control build's step and cost counts are identical to
an xpack-built guest).

## Why it pays

The transpiler folds a `csrs 0x81x, src` marker plus the `add`/`addi` that
follows into one DMA operation. The two forms do **not** cost the same:

| form | transpiles to | steps |
|---|---|---|
| `csrs 0x813,src` + `addi x0,dst,IMM` | one zisk instruction, count in the extended arg | 1 |
| `csrs 0x813,src` + `add x0,dst,reg` | two, the first *writes* the count to `EXTRA_PARAMS_ADDR` | 2 |

A call into the `ziskos` thunk always pays the second form plus `jal` and `ret`,
so a compile-time length that reaches the precompile in place costs 1 step where
the call costs 4. Measured on block 25659678: 5.75 steps saved per copy.

## What it covers

* `cpymem` / `movmem` — the big one. `evmc::bytes32` is `uint8_t[32]`, alignment
  1, so GCC cannot use word moves and gives up to a libcall: 1.5M such copies per
  block went through the thunk.
* `setmem` — both marker forms; a run-time fill byte cannot be encoded in the
  `addi` immediate and still falls back to the thunk's 256-entry jump table.
* `cmpmemsi` — the result register rides on the marker's `csrrs`. The machine
  returns `byte_a - byte_b` sign extended to 64 bits, already canonical for
  SImode, so no `sext.w` is needed.
* `MOVE_RATIO` / `CLEAR_RATIO` / `SET_RATIO` drop to 2 under the flag, so only
  copies that fit a couple of word moves stay inline. Mirrors
  `MaxStoresPerMemcpy = 2` in the LLVM patch. It matters: 78.6% of this guest's
  copies are <= 8 bytes, and for those `ld`+`sd` beats any marker.

## Measured (ziskemu from zisk24, evmone backend)

Block 25659678:

| build | steps | vs control | cost | vs control |
|---|---|---|---|---|
| control (this compiler, no flag) | 213,257,945 | — | 48,626,662,078 | — |
| `-mzisk-dma`, cpymem+movmem only | 195,899,507 | -8.14% | 47,529,798,319 | -2.26% |
| `-mzisk-dma`, all four | **187,547,656** | **-12.06%** | **47,086,668,726** | **-3.17%** |

Block 25697424:

| build | steps | vs control | cost | vs control |
|---|---|---|---|---|
| control | 161,478,493 | — | 31,935,329,907 | — |
| `-mzisk-dma`, all four | **141,121,333** | **-12.61%** | **30,621,244,398** | **-4.11%** |

Block hash identical to the control in every build. The control's own numbers are
identical to an xpack-built guest, so the whole delta is the flag.

Where it comes from, by operation (block 25659678, control -> patched):

    dma_xmemcpy    1,670,779 -> 3,421,414  (+ 218,012 in the register form)
    dma_xmemset      150,139 -> 1,967,015
    dma_xmemcmp            0 ->    95,900  (98,179 went through the thunk before)

memset is the surprise: GCC was expanding nearly 2M small memsets by pieces, and
turning each into one operation is worth -8.35M steps on its own.

## Using it

No fork of GCC is involved: the patch above is the whole delta, applied to a
pristine upstream tarball. Build the compiler once —

```bash
cpp-guest/patches/gcc/build-toolchain.sh
```

It downloads GCC 14.3.0, patches it, builds and installs into
`~/.local/xPacks/zisk-dma-gcc-14.3.0` (override with `ZISK_DMA_GCC_PREFIX`), then
verifies that the flag both parses and emits a marker. ~10 minutes. Run it again
any time: it detects the installed compiler and returns immediately, so it is
safe to call from a build script or CI step.

Then put it first on `PATH` and turn the flag on:

```bash
export PATH="$HOME/.local/xPacks/zisk-dma-gcc-14.3.0/bin:$PATH"
cmake -S cpp-guest/zisk -B cpp-guest/zisk/build-dma \
      -DCMAKE_TOOLCHAIN_FILE=$PWD/cpp-guest/zisk/toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release -DZEG_ZISK_DMA=ON
cmake --build cpp-guest/zisk/build-dma -j --target zisk_eth_guest.elf
```

`ZEG_ZISK_DMA` is OFF by default, so a stock xPack toolchain keeps building the
guest exactly as before. With it ON, configure probes the compiler for the flag
and fails with a message pointing at the script rather than at a wall of
assembler errors.

### What the script builds, and what it borrows

Only the compiler proper (`make all-gcc`) — no libgcc, no newlib, no libstdc++.
That is what turns an hour into ten minutes, and it works because the guest links
`-nostdlib -nostartfiles` with no libraries at all: the only things still needed
from a full toolchain are the C++ *headers* and the assembler and linker, which
the script symlinks from the xPack toolchain. Its version must match GCC 14.3.0
exactly, which is why the script checks for it and refuses to guess.

The host compiler matters too: GCC 14's bundled `libcody` does not build with a
host g++ newer than ~14 (`u8""` literals became `char8_t`). The script picks
g++-13/12/11 if one is installed; otherwise set `CXX`/`CC` yourself.

## Two traps worth remembering

* The `P` mode iterator expands a pattern once per mode, so a `define_insn` using
  it needs `<mode>` in its name or the build dies on duplicate definitions.
* The immediate form's length operand must be `const_arith_operand`, not
  `const_int_operand`. With the looser predicate GCC propagates a constant into
  the register form and then re-recognizes it as the immediate one, emitting
  `addi zero,a0,4096` — outside simm12, and the assembler rejects it.

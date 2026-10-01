# Building the guest with the ZisK DMA lowering

`-mzisk-dma` makes GCC lower block memory operations (`memcpy`, `memmove`,
`memset`, equality `memcmp`, and the struct copies GCC turns into them) to the
ZisK DMA precompile markers in place, instead of calling the `mem*` thunks in
`dma/`. It cuts about 12% of a block's steps and 3–4% of its area, and it does
not change the block hash.

The flag only exists in a patched GCC 14.3.0. A stock compiler cannot build with
it, so the CMake option `ZEG_ZISK_DMA` is **OFF** by default. For how the
lowering works and where the numbers come from, see
[`../patches/gcc/README.md`](../patches/gcc/README.md).

## Prerequisites

- **xPack `riscv-none-elf-gcc` 14.3.0-1**, unpacked at
  `~/.local/xPacks/xpack-riscv-none-elf-gcc-14.3.0-1` (download the linux-x64
  tarball from the
  [xPack releases](https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases)).
  The patched compiler reuses its C++ headers, assembler and linker, so it must be
  exactly this version. If it is installed somewhere else, set `ZISK_XPACK_DIR`.
- **A host `g++-13`, `g++-12` or `g++-11`** with the matching `gcc`. GCC 14's
  sources do not build with a newer host compiler. The script picks one of these
  automatically; otherwise set `CC` and `CXX`.
- `curl`, `tar`, `make`, and a few GB free for the GCC build tree (`/tmp` by
  default).
- The usual guest prerequisites from [`README.md`](README.md): the host build
  configured once so that evmone's sources are fetched.

## 1. Build the patched compiler (once)

```bash
cpp-guest/patches/gcc/build-toolchain.sh
```

The script downloads GCC 14.3.0, applies
`0001-riscv-zisk-dma-lowering.patch`, builds only the compiler (about 10
minutes) and installs it into `~/.local/xPacks/zisk-dma-gcc-14.3.0`. Before it
finishes, it checks that the new compiler accepts `-mzisk-dma` and really emits
the DMA markers.

It is safe to run again. If the compiler is already installed, it returns at
once and prints the `export` line from step 2. Pass `--force` to rebuild it, for
example after changing the patch.

| Variable | Default | Meaning |
|---|---|---|
| `ZISK_DMA_GCC_PREFIX` | `~/.local/xPacks/zisk-dma-gcc-14.3.0` | where the patched compiler is installed |
| `ZISK_XPACK_DIR` | `~/.local/xPacks/xpack-riscv-none-elf-gcc-14.3.0-1` | the xPack toolchain it borrows from |
| `ZISK_DMA_GCC_BUILD_DIR` | `$TMPDIR/zisk-dma-gcc-build` | sources and build tree |
| `CC`, `CXX` | first `gcc-N`/`g++-N` found, N = 13, 12, 11 | host compiler for the build |

## 2. Put it first on `PATH`

```bash
export PATH="$HOME/.local/xPacks/zisk-dma-gcc-14.3.0/bin:$PATH"
riscv-none-elf-g++ --version | head -1   # should print 14.3.0
```

`toolchain.cmake` uses the first `riscv-none-elf-g++` it finds on `PATH`, so the
order matters.

## 3. Configure and build the guest with `ZEG_ZISK_DMA=ON`

Use a **new** build directory. CMake caches the compiler on the first configure,
so turning the option on in a directory configured with the stock xPack would
keep the old compiler.

```bash
# evmone backend (default)
cmake -S cpp-guest/zisk -B cpp-guest/zisk/build-dma \
      -DCMAKE_TOOLCHAIN_FILE=$PWD/cpp-guest/zisk/toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release -DZEG_ZISK_DMA=ON
cmake --build cpp-guest/zisk/build-dma -j --target zisk_eth_guest.elf

# zevm backend
cmake -S cpp-guest/zisk -B cpp-guest/zisk/build-zevm-dma \
      -DCMAKE_TOOLCHAIN_FILE=$PWD/cpp-guest/zisk/toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release -DEVM_BACKEND=zevm -DZEG_ZISK_DMA=ON
cmake --build cpp-guest/zisk/build-zevm-dma -j --target zisk_eth_guest.elf
```

The configure output should include:

```
-- ZisK DMA lowering: ON (-mzisk-dma)
```

## 4. Check the result

Count the DMA markers in the ELF. With the lowering there are many thousands.
A stock build has a few hundred: the `dma/*.s` thunks plus the explicit
`zisk_xmem*` calls in the source (on the current tree, about 9,000 against
about 300):

```bash
riscv-none-elf-objdump -d cpp-guest/zisk/build-dma/zisk_eth_guest.elf \
  | grep -cE 'csrr?s\s.*0x81[3-6]'
```

Then run a block under `ziskemu` as described in [`README.md`](README.md#run--benchmark)
and compare the hash with the host build. They must match. Use a `ziskemu` recent
enough to implement the DMA (0x813–0x816) and `jump_dest_bitmap` (0x81C)
precompiles. An older emulator treats an unknown CSR as a no-op, so you get a
wrong hash without any error.

## Troubleshooting

- **`ZEG_ZISK_DMA=ON but ... does not accept -mzisk-dma`**: CMake is using a stock
  compiler. Either the patched one is not first on `PATH`, or the build directory
  was configured with another compiler before. Fix `PATH` and use a new build
  directory.
- **`xPack 14.3.0 not found`**: install the xPack 14.3.0-1 toolchain or point
  `ZISK_XPACK_DIR` at it. No other version works.
- **`no g++-13/12/11 found for the host build`**: install one, for example
  `sudo apt install g++-13`, or set `CC` and `CXX`.
- **The build fails inside `libcody` with `char8_t` errors**: the host compiler is
  too new. Set `CXX=g++-13 CC=gcc-13` and rerun with `--force`.
- **Configure or build logs**: they are in `$ZISK_DMA_GCC_BUILD_DIR/build/`
  (`configure.log`, `build.log`, `install.log`).

# cpp-guest on ZisK (zkVM)

Builds the C++ block guest as a freestanding RISC-V ELF (`rv64ima_zicsr_zbb_zbs_zbkb`)
that runs in the ZisK emulator (`ziskemu`) and is proved by `cargo-zisk`. It lives
alongside the native host build (`cpp-guest/CMakeLists.txt`), which is unchanged;
the ZisK path is selected by the `ZEG_ZISK` compile macro.

The guest reaches the ZisK machine only through a C ABI, never by issuing
precompile CSRs or fcalls itself:

- the Ethereum Foundation zkVM standard: `zkvm_accelerators.h` (the precompile
  crypto) and `zkvm_io.h` (`read_input` / `write_output`);
- ZisK's extensions to it: `zkvm_u256_le.h` (256-bit EVM arithmetic on
  little-endian limbs), `zkvm_mem.h` (memory operations) and `zkvm_evm.h`
  (JUMPDEST analysis).

These headers, `zkvm_calls.s` and `zkvm_mem.s` are vendored from zisk's
`ziskasm/lang/c` (`include/`, `src/`) and must stay identical to the zisk version
the guest runs on. An ABI function is implemented in one of three ways, and the
guest source is the same for all of them:

- a **zkvmcall thunk** (`zkvm_calls.s`, `csrs <id>, x0; ret`): the transpiler
  turns the `csrs` into a jump to a hand-written `.zisk` routine of the ZisK
  library (the crypto, the U256 division family and `exp`, the I/O);
- an **inline zkvmcall** (the other U256 operations): a `csrs` per argument,
  which the transpiler replaces by the `.zisk` routine's body at the call site;
- **inline in the header** (`zkvm_keccak_f1600`, the memory functions, JUMPDEST):
  the precompile's own marker, a `csrs` plus the `add`/`addi` that follows,
  which the transpiler folds into one operation.

So the ELF only runs under ZisK, whose transpiler gives these instructions their
meaning; every `ziskemu` / `cargo-zisk` includes the ZisK library.

## Prerequisites

- GCC 14 or 16 for bare-metal RISC-V on `PATH`, e.g. the xPack
  `riscv-none-elf-gcc` (`toolchain.cmake` also finds `riscv64-unknown-elf-` and
  `riscv64-elf-`). Ubuntu's `riscv64-unknown-elf-g++` 13 ships no libstdc++
  headers; see `AGENTS.md` for the GCC versions to avoid.
- The host build configured once, so evmone's source is fetched and this
  branch's patches (`cpp-guest/patches/`) are applied:
  `cmake -S cpp-guest -B cpp-guest/build` (populates `build/_deps/evmone-src` and
  the intx headers under `~/.hunter`).
- A `ziskemu` from the matching `../zisk` checkout:
  `cargo build --release -p ziskemu --manifest-path ../zisk/Cargo.toml`
  → `../zisk/target/release/ziskemu`.

## Build

```bash
cmake -S cpp-guest/zisk -B cpp-guest/zisk/build \
      -DCMAKE_TOOLCHAIN_FILE=$(pwd)/cpp-guest/zisk/toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release
cmake --build cpp-guest/zisk/build -j8
# -> cpp-guest/zisk/build/zisk_eth_guest.elf
```

The evmone source is found in `cpp-guest/build*/_deps/evmone-src`; pass
`-DEVMONE_SRC=<path>` to use another one. Options:

| Option | Default | Effect |
|---|---|---|
| `EVM_BACKEND` | `evmone` | `evmone` or `zevm` (the hand-written interpreter); use a separate build directory per backend |
| `ZEG_JUMPDEST_SW` | `OFF` | `ON` runs the software JUMPDEST walk instead of the precompile, for A/B step counts |
| `ZEG_BSWAP_BUILTIN` | `OFF` | `ON` uses plain `__builtin_bswap64` instead of the zero-shortcut `rev8` inline asm, for A/B step counts (see `include/zeg/bswap.hpp`) |
| `ZEG_ZISK_DMA` | `OFF` | `ON` passes `-mzisk-dma` to a patched GCC (`../patches/gcc/`), which lowers block `mem*`, including the copies it synthesizes itself, to the same DMA markers `zkvm_mem.h` inlines; see [`README-zisk-dma.md`](README-zisk-dma.md) |

## Run / benchmark

The guest reads its input with `read_input`, and `ziskemu` expects the `-i` file
framed as `[u64 LE length][payload]`, where `payload` is the cpp-guest container
(starting with the `ZEG0` magic). Frame any `*.bin` and run:

```bash
IN=build/verify/<block>/input.bin
python3 -c "import struct,sys; d=open('$IN','rb').read(); \
  open('/tmp/blk.zisk.bin','wb').write(struct.pack('<Q',len(d))+d)"

ZE=../zisk/target/release/ziskemu
$ZE -e cpp-guest/zisk/build/zisk_eth_guest.elf -i /tmp/blk.zisk.bin -o /tmp/blk.out -X
xxd -p -c32 /tmp/blk.out        # the 32-byte block hash (public output)
```

`-X` prints the steps and the cost breakdown (main, precompiles by opcode,
memory); `-m` prints timing metrics. The output must match the native guest:
`./cpp-guest/build/zisk_eth_guest $IN | tail -1`.

## What goes through the ABI

| Guest feature | ABI | Where |
|---|---|---|
| Keccak-256 (MPT, tx/header hashes, CREATE, code hashes, `KECCAK256`) | `zkvm_keccak256` | `keccak_zisk.cpp` (drop-in for evmone's `keccak.c`) |
| SHA-256 (0x02, KZG versioned hash, EIP-7685 requests) | `zkvm_sha256` | `sha256_zisk.cpp` |
| RIPEMD-160 (0x03) | `zkvm_ripemd160` | `ripemd160_zisk.cpp` |
| ECRECOVER (0x01), tx senders, EIP-7702 signers | `zkvm_secp256k1_ecrecover` | `secp256k1.cpp` (the host build delegates to evmone) |
| MODEXP (0x05) | `zkvm_modexp` | `modexp_zisk.cpp` |
| BN254 ecAdd / ecMul / ecPairing (0x06–0x08) | `zkvm_bn254_*` | `bn254_eip196.cpp`, `bn254/add_affine_spec.hpp` |
| BLAKE2 F (0x09) | `zkvm_blake2f` | `blake2b_zisk.cpp` |
| KZG point evaluation (0x0a) | `zkvm_kzg_point_eval` | `bls12_381_kzg.cpp` (the versioned-hash check stays in the guest) |
| EIP-2537 BLS12-381 (0x0b–0x11) | `zkvm_bls12_*` | `bls12_381_eip2537.cpp`, `bls12_381/zkvm_marshal.hpp` |
| P-256 verify (0x100) | `zkvm_secp256r1_verify` | `secp256r1_p256.cpp` |
| EVM MUL, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP (and zevm's full-width ADD/SUB) | `zkvm_u256_le_*` | evmone patch `03-evmone-zisk-u256-abi.patch`, `evm/fused_dispatch.inl`, `../src/zevm/instructions/arith.inl.hpp` |
| `memcpy` / `memmove` / `memcmp` / `memset`, and the MPT's fixed-size copies | `zkvm_mem.h` | `zkvm_mem.s` (weak libc symbols), `../include/zeg/zisk_dma.hpp` |
| JUMPDEST analysis | `zkvm_evm_jumpdest_bitmap` | `evm/jump_dest_bitmap.hpp` (evmone patch 05, zevm) |
| Block input, public output | `read_input`, `write_output` | `../include/zeg/zisk_io.hpp` |

Each wrapper marshals between evmone's types and the EF byte encodings
(big-endian field elements and scalars; EIP-197 imaginary-first Fp2 for bn254;
EIP-2537's 64-byte padded field elements for BLS, whose 16 zero pad bytes the
guest checks, since the EF encoding drops them). Validation of points and
signatures is the ABI's. zevm's inline U256 operations run in small `noinline`
helpers: expanded inside its dispatch loop they made GCC spill registers across
the whole loop.

UART debug output (`uart_putc`, at `0xA0400200`) is a plain memory-mapped write,
not part of the proof.

## Layout

| File | Purpose |
|------|---------|
| `toolchain.cmake` | RISC-V cross toolchain (no `-ffreestanding`; `-nostdlib` at link) |
| `CMakeLists.txt`  | standalone build; compiles the guest + needed evmone sources, Hunter-free |
| `_start.s`, `zisk.ld` | entry + memory map |
| `runtime.cpp`     | bump allocator, str*, libgcc builtins, no-op libc stdio stubs, C++ ABI, integer-only `_Prime_rehash_policy` |
| `stdcxx_stubs.cpp`| `halt()` stubs for dead iostream/pmr paths |
| `tracer_stubs.cpp`| stubs for evmone's tracer factories, so `tracing.cpp` is not linked |
| `zkvm_accelerators.h`, `zkvm_io.h`, `zkvm_u256_le.h`, `zkvm_mem.h`, `zkvm_evm.h` | the ABI headers (vendored) |
| `zkvm_calls.s`    | the zkvmcall thunks (vendored) |
| `zkvm_mem.s`      | weak libc `mem*` on the DMA ops, and `zkvm_memset_any` (vendored) |
| `*_zisk.cpp`, `secp256k1.cpp`, `secp256r1_p256.cpp`, `bn254_eip196.cpp`, `bls12_381_*.cpp` | the precompile wrappers, drop-ins for evmone's symbols (table above) |
| `bls12_381/zkvm_marshal.hpp` | EIP-2537 ↔ EF BLS repacking; host test `bls12_381/test/zkvm_marshal_test.cpp` (`g++ -std=c++20 <file>`) |
| `bn254/add_affine_spec.hpp` | the ECADD specialization, force-included into evmone's `precompiles.cpp` |
| `bigint/backend.hpp` | portable 256-bit software for zevm's **host** build (the ZisK build uses the U256 ABI) |
| `evm/fused_dispatch.inl` | evmone's fused opcode sequences (patch 06) |
| `evm/jump_dest_bitmap.hpp` | JUMPDEST analysis through `zkvm_evm.h` |
| `../include/zeg/zisk_io.hpp` | input/output through `zkvm_io.h`, and the UART debug output |
| `../include/zeg/zisk_dma.hpp` | fixed-size memory operations through `zkvm_mem.h` (host: the standard functions) |

# cpp-guest on ZisK (zkVM)

Builds the C++ block guest as a freestanding **RISC-V `rv64ima_zicsr`** ELF that
runs in the ZisK emulator (`ziskemu`) for benchmarking, and eventually proving.
This is the *self-contained baseline*: own `_start` + `mem*` + **software**
secp256k1, no `libziskos`. Keccak is wired to the ZisK accelerator (CSR 0x800,
see `keccak_zisk.cpp`); secp256k1 is next. It exists alongside the
native host build (`cpp-guest/CMakeLists.txt`) — that is unchanged; the ZisK
path is selected by the `ZEG_ZISK` compile macro.

## Prerequisites

- `riscv64-unknown-elf-g++` (or `riscv-none-elf-` / `riscv64-elf-`) on `PATH`.
- The host build configured once so evmone's source is fetched:
  `cmake -S cpp-guest -B cpp-guest/build` (populates `build/_deps/evmone-src`
  and the intx headers under `~/.hunter`).
- A `ziskemu` that matches the `../zisk` repo memory map (`INPUT_ADDR=0x40000000`).
  The SDK `~/.zisk/bin/ziskemu` (0.2.0) is **too old** (`0x90000000`); build a
  current one:
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

## Run / benchmark

The guest reads its input from the ZisK memory-mapped region, which expects the
`-i` file framed as `[u64 LE length][payload]`, where `payload` is the cpp-guest
container (starting with the `ZEG0` magic). Frame any `*.bin` and run:

```bash
IN=build/verify/<block>/input.bin
python3 -c "import struct,sys; d=open('$IN','rb').read(); \
  open('/tmp/blk.zisk.bin','wb').write(struct.pack('<Q',len(d))+d)"

ZE=../zisk/target/release/ziskemu
$ZE -e cpp-guest/zisk/build/zisk_eth_guest.elf -i /tmp/blk.zisk.bin -o /tmp/blk.out -x
xxd -p -c32 /tmp/blk.out        # the 32-byte block hash (public output)
```

`-x` prints opcode/step statistics (the benchmark); `-m` prints timing metrics.
The output must match the native guest:
`./cpp-guest/build/zisk_eth_guest $IN | tail -1`.

## What's stubbed (first milestone)

- **Heavy precompiles** BLS12-381 (EIP-2537), KZG point-eval (EIP-4844), and
  MODEXP (0x05) → failure stubs (`precompile_stubs.cpp`). Blocks that use them
  will mismatch; everything else runs.
- **secp256k1 uses the ZisK accelerators** (`secp256k1.cpp`): field/scalar
  arithmetic and EC add/double via the precompiles (CSR 0x802/0x803/0x804) plus
  fcall hints (FN_INV, MSB_POS_256), a faithful port of ziskos's `zisklib`. The
  same file builds a portable software baseline with `-DZEG_SECP256K1_SW=ON`.
- **Keccak uses the ZisK accelerator** (`keccak_zisk.cpp`, CSR 0x800) — a
  drop-in for evmone's `keccak.c`, so all callers (state/MPT hashing, tx/header
  hashes, CREATE addresses, code hashes, the EVM `KECCAK256` opcode, …) hit it.
- No crypto remains in software on the ZisK build.

## Layout

| File | Purpose |
|------|---------|
| `toolchain.cmake` | rv64ima cross toolchain (no `-ffreestanding`; `-nostdlib` at link) |
| `CMakeLists.txt`  | standalone build; compiles guest + needed evmone sources, Hunter-free |
| `_start.s`, `zisk.ld` | entry + memory map (from hello-zisk-c) |
| `runtime.cpp`     | bump allocator, `mem*`, no-op libc stdio stubs, C++ ABI |
| `compiler_rt.cpp` | libgcc builtins, soft-float, 128-bit div/shift, `_Prime_rehash_policy` |
| `stdcxx_stubs.cpp`| `halt()` stubs for dead iostream/pmr paths (tracer, etc.) |
| `secp256k1.cpp`   | secp256k1 `ecdsa_verify`: ZisK precompiles+fcalls, or software with `-DZEG_SECP256K1_SW` |
| `keccak_zisk.cpp` | Keccak-256 via the ZisK keccakf precompile (CSR 0x800) |
| `precompile_stubs.cpp` | bls/kzg/modexp failure stubs |
| `include/zeg/zisk_io.hpp` | memory-mapped input/output (`ZEG_ZISK`) |

# ziskethone on Zisk (zkVM RISC-V target)

This directory builds the ziskethone C++ Ethereum block guest for the
[Zisk](https://github.com/0xPolygonHermez/zisk) zkVM (`riscv64ima` bare metal).
It is a **separate build** from `cpp-guest/CMakeLists.txt` (which is the
host-only build that fetches evmone 0.21 via Hunter).

The Zisk build reuses zilkworm's already-Zisk-patched EVM stack — evmone 0.19
(with precompile syscalls), `silkworm_core`, `intx`, the patched `blst`, and the
cross-compile toolchain — pulled in as the `third_party/zilkworm` git submodule.
The guest's own sources are unchanged except for `#ifdef ZISK`-gated I/O, a
bare-metal halt/debug shim, and a syscall-backed secp256k1 sender recovery; the
host build path is preserved.

## Prerequisites

- **RISC-V cross toolchain**: xPack `riscv-none-elf-gcc` (tested 15.2.0).
  Point `ZISK_TOOLCHAIN_PREFIX` at its `bin/` directory.
- **Zisk emulator** `ziskemu` (from a Zisk install; usually on `PATH` at
  `~/.zisk/bin/ziskemu`).
- **CMake ≥ 3.28**, Ninja, Python 3.

## One-time setup

```bash
# From the ziskethone repo root: pull the zilkworm submodule + its nested
# submodules. --recursive is REQUIRED (evmone has a nested evmc submodule,
# fetched over HTTPS).
git submodule update --init --recursive third_party/zilkworm
```

## Build

```bash
cd cpp-guest
ZISK_TOOLCHAIN_PREFIX=/path/to/riscv-none-elf-gcc/bin \
  cmake -B build-zisk -S zisk \
    -DCMAKE_TOOLCHAIN_FILE=$PWD/../third_party/zilkworm/prover/guest_zisk/cmake/zisk-toolchain.cmake \
    -GNinja
ZISK_TOOLCHAIN_PREFIX=/path/to/riscv-none-elf-gcc/bin cmake --build build-zisk
# Output: cpp-guest/build-zisk/zisk_eth_guest.elf
```

`ZILKWORM_ROOT` defaults to the in-tree submodule (`third_party/zilkworm`), so
no external checkout is needed. To build against an external zilkworm checkout
during development, pass `-DZILKWORM_ROOT=/path/to/zilkworm`.

## Generate and run an input

```bash
# 1. Generate a raw ZEG0 input for a block (host-side, needs a debug RPC).
ETH_RPC_URL=http://your.rpc:8545 \
  make input BLOCK=25193400 OUTPUT=/tmp/block_25193400.bin

# 2. Frame it for ziskemu ([u64 LE len][payload], 8-byte aligned).
python3 cpp-guest/zisk/scripts/wrap_input.py \
  /tmp/block_25193400.bin /tmp/block_25193400.wrapped.bin

# 3. Run on the emulator and dump the 32-byte public output (block hash).
ziskemu -e cpp-guest/build-zisk/zisk_eth_guest.elf \
  -i /tmp/block_25193400.wrapped.bin -o /tmp/out.bin
xxd -l 32 /tmp/out.bin   # == the canonical execution-layer block hash

# Performance report (steps / cost / per-opcode):
ziskemu --sdk -X -S --top-functions \
  -e cpp-guest/build-zisk/zisk_eth_guest.elf -i /tmp/block_25193400.wrapped.bin
```

## Precompile coverage

All EVM precompiles are Zisk-syscall-accelerated via zilkworm's patched evmone
(keccak, sha256, ecrecover/secp256k1, modexp, bn254 add/mul/pairing, blake2f,
secp256r1) and patched blst (bls12-381 EIP-2537, and KZG point-evaluation
EIP-4844 which uses the blst pairing). The sole exception is **ripemd160**,
which runs in software because Zisk has no ripemd syscall.

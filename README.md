# zisk_eth_guest

ZisK guest program for verifying an Ethereum block.

The repository is split in two components that communicate through a binary
file on disk:

```
┌──────────────────────┐    block_input.bin    ┌────────────────────────┐
│  rust-input-gen      │ ────────────────────▶ │  cpp-guest (ZisK)      │
│  (host, Rust)        │                       │  (zkVM, C++)           │
│                      │                       │                        │
│  • talks to an ETH   │                       │  • reads private input │
│    JSON-RPC node     │                       │  • re-executes block   │
│  • fetches header,   │                       │  • commits 2 public    │
│    txs, witness…     │                       │    outputs:            │
│  • writes binary     │                       │    – previousBlockHash │
│    container         │                       │    – nextBlockHash     │
└──────────────────────┘                       └────────────────────────┘
```

The wire format between the two halves is documented in
[BINARY_FORMAT.md](BINARY_FORMAT.md). It is designed to be **zero-parse on the
guest side**: the C++ program can `mmap` the file and access fields via direct
pointer casts to packed structs.

## Repository layout

| Path                | Purpose                                                  |
|---------------------|----------------------------------------------------------|
| `rust-input-gen/`   | Rust binary that fetches block data via RPC and writes `block_input.bin`. |
| `cpp-guest/`        | C++ ZisK guest program (currently a placeholder + host-side sanity reader). |
| `BINARY_FORMAT.md`  | On-disk format specification.                            |
| `Makefile`          | Convenience targets to build / run both halves.          |

## Quick start

```bash
# 1. Generate an input file (requires a debug-enabled ETH RPC endpoint)
export ETH_RPC_URL="https://your.rpc.node"
make input BLOCK=19000000

# 2. Build the C++ host sanity reader and inspect the file
make cpp
./cpp-guest/build/guest_host_sanity build/block_input.bin
```

## Status

- ✅ Binary container format defined and implemented (Rust writer + C++ reader).
- 🚧 RPC fetching is scaffolded; full `debug_executionWitness` parsing TODO.
- 🚧 Actual ZisK C++ guest entrypoint and RLP / Keccak / EVM execution TODO.

## Requirements

- Rust 1.75+ with `cargo`
- CMake 3.20+ and a C++20 compiler (for the host sanity reader)
- An Ethereum JSON-RPC endpoint that exposes the `debug` namespace
  (`debug_executionWitness`, `debug_getRawHeader`, …) for full stateless input

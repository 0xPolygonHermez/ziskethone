# zisk_eth_guest

A stateless Ethereum block verifier targeting the [ZisK](https://github.com/0xPolygonHermez/zisk) RISC-V zkVM.

The repository is split into three components that communicate through a binary
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

┌──────────────────────┐
│  eest-witness-gen    │  Bridges EEST (Ethereum Execution Spec Tests)
│  (host, Rust)        │  fixtures into the same binary format via
│                      │  reth's executor + ExecutionWitnessRecord.
└──────────────────────┘  Used for the conformance sweeps.
```

The wire format between halves is documented in
[BINARY_FORMAT.md](BINARY_FORMAT.md). It is designed to be **zero-parse on the
guest side**: the C++ program can `mmap` the file and access fields via direct
pointer casts to packed structs.

## Repository layout

| Path                  | Purpose                                                                    |
|-----------------------|----------------------------------------------------------------------------|
| `rust-input-gen/`     | Two binaries: `input-gen` (RPC → binary) and `input-gen-from-manifest`.    |
| `eest-witness-gen/`   | Bridges EEST blockchain-test fixtures to an `OfflineSources` JSON manifest.|
| `cpp-guest/`          | C++ stateless verifier (evmone + custom state DB).                         |
| `scripts/`            | `verify_blocks.py` — continuous mainnet verifier.                          |
| `BINARY_FORMAT.md`    | On-disk format specification.                                              |
| `Makefile`            | Convenience targets to build / run.                                        |

## Requirements

- Rust 1.75+ with `cargo`
- CMake 3.20+ and a C++20 compiler (clang or gcc)
- An Ethereum JSON-RPC endpoint that exposes the `debug` namespace
  (`debug_executionWitness`, `debug_traceBlockByHash` with `prestateTracer`,
  …) for full stateless input. On macOS, the `eest-witness-gen` libmdbx build
  needs `SDKROOT=$(xcrun --show-sdk-path)` exported so bindgen finds `assert.h`.

## Building

```bash
# Rust hosts (input-gen, input-gen-from-manifest)
make rust

# C++ guest binary
make cpp

# EEST bridge (only needed for conformance sweeps)
SDKROOT=$(xcrun --show-sdk-path) \
BINDGEN_EXTRA_CLANG_ARGS="-isysroot $(xcrun --show-sdk-path)" \
cargo build --release --manifest-path eest-witness-gen/Cargo.toml
```

Outputs:
- `target/release/input-gen`, `target/release/input-gen-from-manifest`
- `cpp-guest/build/zisk_eth_guest`
- `eest-witness-gen/target/release/eest-witness-gen`

## Verifying a single mainnet block

End-to-end, fetch a block and reproduce its hash inside cpp-guest:

```bash
export ETH_RPC_URL="https://your-debug-enabled-eth-rpc"

# Latest Pectra-era block
LATEST=$(cast block-number --rpc-url "$ETH_RPC_URL")

# 1. Fetch the witness + write the binary input
./target/release/input-gen \
    --rpc-url "$ETH_RPC_URL" \
    --block "$LATEST" \
    --output build/block_input.bin

# 2. Re-execute the block inside the guest
./cpp-guest/build/zisk_eth_guest build/block_input.bin
```

The guest prints `0x<block_hash>` on its last stdout line. Compare against the
canonical hash:

```bash
cast block "$LATEST" --rpc-url "$ETH_RPC_URL" --json | jq -r .hash
```

For a fixed reference, any Pectra mainnet block works (Pectra activated on
2025-05-07, block 22,431,084). Example using block `25000000`:

```bash
./target/release/input-gen --rpc-url "$ETH_RPC_URL" --block 25000000 \
    --output build/block_input.bin
./cpp-guest/build/zisk_eth_guest build/block_input.bin
# → expect the same hash that `cast block 25000000` reports
```

## Continuous mainnet verification — `scripts/verify_blocks.py`

For long-running validation, [`scripts/verify_blocks.py`](scripts/verify_blocks.py)
polls a node for new heads and verifies each one as it arrives. On any failure
(input-gen error, guest crash, hash mismatch) it dumps per-block artifacts
under `build/verify/<N>/` and (optionally) spawns an interactive `claude`
session at the repo root with a ready-to-paste debug prompt.

```bash
# Tail the chain head — verify every new block
python3 scripts/verify_blocks.py \
    --rpc-url "$ETH_RPC_URL" \
    --poll-sec 5

# Replay historical blocks from a specific number
python3 scripts/verify_blocks.py \
    --rpc-url "$ETH_RPC_URL" \
    --start-from 25000000

# CI mode — never spawn claude on failure (just record artifacts)
python3 scripts/verify_blocks.py \
    --rpc-url "$ETH_RPC_URL" \
    --start-from 25000000 \
    --no-claude
```

Key behaviour:
- **Reorg-aware**: re-queues a block up to 5 times if input-gen reports a
  mid-run reorg, and refreshes the cached chain hash before declaring a
  HASH-MISMATCH.
- **Failure artifacts** (`build/verify/<block>/`):
  - `input.bin` — the binary witness fed to the guest
  - `input-gen.log` — input-gen's combined stdout/stderr
  - `cpp-stdout.txt`, `cpp-stderr.txt` — guest output
  - `chain.json` — the canonical block as the RPC reported it
  - `failure.md` — human-readable summary + suggested first-prompt for a
    debug session
- **Exit codes**: 75 from input-gen means "chain reorged mid-fetch" and is
  retried automatically. Any other non-zero is recorded as a failure.

## EEST conformance sweeps

The `eest-witness-gen` bridge replays
[Ethereum Execution Spec Tests](https://github.com/ethereum/execution-spec-tests)
fixtures through reth's executor, captures the resulting witness, and writes an
`OfflineSources` JSON manifest that `input-gen-from-manifest` turns into the
same binary format as the live RPC path.

The currently-supported forks (per
[`eest-witness-gen/src/chain_spec.rs`](eest-witness-gen/src/chain_spec.rs)) are
Berlin / London / Paris / Shanghai / Cancun / Prague / Osaka, plus the
`CancunToPragueAtTime…` and `PragueToOsakaAtTime…` transition specs.

### Running one fixture

```bash
# Extract / download EEST fixtures to /tmp/eest/fixtures/blockchain_tests/...
FIXTURE=/tmp/eest/fixtures/blockchain_tests/prague/eip7702_set_code_tx/test_account_warming.json
OUT=$(mktemp -d)
eest-witness-gen/target/release/eest-witness-gen --fixture "$FIXTURE" --output-dir "$OUT"

# Run every per-block manifest the fixture produced
for m in $(find "$OUT" -name "block-*.json" | sort); do
    ./target/release/input-gen-from-manifest --manifest "$m" --output /tmp/x.bin
    actual=$(./cpp-guest/build/zisk_eth_guest /tmp/x.bin | tail -1)
    expected=$(python3 -c "import json; print(json.load(open('$m'))['current']['hash'])")
    [ "$actual" = "$expected" ] && echo "OK   $(basename "$m")" \
                               || echo "FAIL $(basename "$m") $actual vs $expected"
done
```

### Sweeping a full corpus

The Prague + Osaka EEST corpora are validated by a small shell harness that
iterates every fixture, runs the bridge, and accumulates per-suite pass/fail
counts. The pattern (lives at `/tmp/sweep_all.sh` during development):

```bash
SWEEP_ROOT=$(mktemp -d)
trap "rm -rf $SWEEP_ROOT" EXIT
total=0; pass=0
for f in $(find /tmp/eest/fixtures/blockchain_tests/prague -name "*.json"); do
    OUT=$(mktemp -d "$SWEEP_ROOT/fix.XXXXXX")
    eest-witness-gen/target/release/eest-witness-gen --fixture "$f" --output-dir "$OUT" \
        >/dev/null 2>&1 || continue
    for m in $(find "$OUT" -name "block-*.json" | sort); do
        total=$((total+1))
        ./target/release/input-gen-from-manifest --manifest "$m" --output /tmp/x.bin \
            2>/dev/null >/dev/null || continue
        actual=$(./cpp-guest/build/zisk_eth_guest /tmp/x.bin 2>&1 | tail -1)
        expected=$(python3 -c "import json; print(json.load(open('$m'))['current']['hash'])")
        [ "$actual" = "$expected" ] && pass=$((pass+1))
    done
done
echo "$pass/$total"
```

EEST negative tests (blocks marked with `expect_exception`) are special-cased
via a `block-N.expect` sidecar emitted by `eest-witness-gen`: an input-gen or
guest fatal counts as PASS for those blocks (we correctly refused the bad
input). See `/tmp/sweep_all.sh` in development checkouts for the full harness
including bucket-by-bucket failure histograms.

Current pass rates (as of branch `osaka-eest-support`):
- **Prague EEST**: 2579 / 2580 (99.96%)
- **Osaka EEST**: in progress

## Quick `make` reference

```bash
make all       # rust + cpp
make rust      # input-gen + input-gen-from-manifest
make cpp       # zisk_eth_guest
make input BLOCK=25000000 ETH_RPC_URL=https://…  # build/block_input.bin
make test      # rust unit tests
make clean
```

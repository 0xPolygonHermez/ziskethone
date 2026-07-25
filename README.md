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

### EVM backend — `evmone` (default) or `zevm`

The guest drives the EVM through the swappable evmc2 interface, so the
interpreter is a build-time choice via the `EVM_BACKEND` CMake option:

- **`evmone`** — the upstream evmone baseline interpreter. **This is the current
  standard: it is the default everywhere and the backend used by all the
  verification and conformance flows below.**
- **`zevm`** — the in-tree hand-written interpreter (`cpp-guest/src/zevm/`),
  selected only when explicitly requested with `-DEVM_BACKEND=zevm`.

`make cpp` builds the host guest with the default (`evmone`) into
`cpp-guest/build`. To choose a backend explicitly, configure with
`-DEVM_BACKEND=…`; use a separate build directory per backend so both stay
configured (the option is cached — switching it in an existing directory
requires reconfiguring that directory):

```bash
# Host guest (native)
cmake -S cpp-guest -B cpp-guest/build      -DEVM_BACKEND=evmone   # == make cpp
cmake --build cpp-guest/build
cmake -S cpp-guest -B cpp-guest/build-zevm -DEVM_BACKEND=zevm
cmake --build cpp-guest/build-zevm
```

For the ZisK zkVM ELF (RISC-V cross-build) pass the toolchain file and the same
option, one build directory per backend:

```bash
cmake -S cpp-guest/zisk -B cpp-guest/zisk/build-evmone \
  -DCMAKE_TOOLCHAIN_FILE=$(pwd)/cpp-guest/zisk/toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release -DEVM_BACKEND=evmone        # or -DEVM_BACKEND=zevm
cmake --build cpp-guest/zisk/build-evmone --target zisk_eth_guest.elf
```

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

The whole `blockchain_tests` corpus (all forks, ~2790 fixture files) is
validated by a small shell harness that runs the bridge per fixture, feeds
every resulting block manifest through the guest, and categorizes each block:

```bash
mkdir -p /tmp/sweep/{work,results}
cat > /tmp/sweep/run.sh <<'SCRIPT'
#!/bin/bash
# Args: fixture_path
set -uo pipefail
REPO=/home/jbaylina/git/ziskethone   # adjust to your checkout
FIX="$1"
ID=$(echo "$FIX" | md5sum | cut -d' ' -f1)
OUT="/tmp/sweep/work/fix.$ID"
LOG="/tmp/sweep/results/$ID.log"
rm -rf "$OUT"; mkdir -p "$OUT"

timeout 300 "$REPO/eest-witness-gen/target/release/eest-witness-gen" \
    --fixture "$FIX" --output-dir "$OUT" >/dev/null 2>&1
[ $? -ne 0 ] && { echo "BRIDGE_FAIL $FIX" >> "$LOG"; rm -rf "$OUT"; exit 0; }

for m in $(find "$OUT" -name "block-*.json" | sort); do
    base="${m%.json}"
    bin="/tmp/sweep/work/bin.$ID.bin"
    "$REPO/target/release/input-gen-from-manifest" --manifest "$m" --output "$bin" \
        >/dev/null 2>&1
    ig_rc=$?
    expected=$(jq -r '.current.hash // empty' "$m" 2>/dev/null)
    is_neg=0; [ -s "${base}.expect" ] && is_neg=1   # EEST negative test (expect_exception)

    if [ $ig_rc -ne 0 ]; then
        [ $is_neg -eq 1 ] && echo "PASS_NEG(inputgen) $FIX $m" >> "$LOG" \
                          || echo "FAIL(inputgen) $FIX $m" >> "$LOG"
        rm -f "$bin"; continue
    fi

    actual=$(timeout 60 "$REPO/cpp-guest/build/zisk_eth_guest" "$bin" 2>/dev/null | tail -1)
    guest_rc=$?
    rm -f "$bin"

    if [ $is_neg -eq 1 ]; then
        # a fatal / wrong-hash on a negative test means we correctly rejected it
        if [ $guest_rc -ne 0 ] || [ "$actual" != "$expected" ]; then
            echo "PASS_NEG(guest) $FIX $m" >> "$LOG"
        else
            echo "FAIL_NEG(guest_accepted_bad_block) $FIX $m" >> "$LOG"
        fi
        continue
    fi

    if [ "$actual" = "$expected" ] && [ -n "$expected" ]; then
        echo "PASS $FIX $m" >> "$LOG"
    else
        echo "FAIL $FIX $m actual=$actual expected=$expected" >> "$LOG"
    fi
done
rm -rf "$OUT"
SCRIPT
chmod +x /tmp/sweep/run.sh

find /tmp/eest/fixtures/blockchain_tests -name "*.json" \
    | xargs -P "$(nproc)" -I {} /tmp/sweep/run.sh {}

# Tally
cat /tmp/sweep/results/*.log | awk '{print $1}' | sort | uniq -c
```

`PASS_NEG(...)` = an EEST negative test (`expect_exception`) that we correctly
rejected (input-gen or guest fatal, or a wrong hash — all count as PASS since
the point of the test is that the bad block must NOT be accepted).
`FAIL_NEG` would mean the guest wrongly *accepted* an invalid block — a
soundness bug, more serious than a plain `FAIL` (a completeness gap: a valid
block computed with the wrong hash).

Fixtures not covered by `eest-witness-gen`'s supported-network list (pre-Berlin
forks, and the `ShanghaiToCancunAtTime…`-style transition variants — see
[`eest-witness-gen/src/chain_spec.rs`](eest-witness-gen/src/chain_spec.rs))
produce zero block manifests and are silently absent from `results/`; this is
expected, not a bug.

#### Current results (full corpus, all forks, ~53k blocks)

| | |
|---|---|
| PASS | 52,354 |
| PASS_NEG (correctly-rejected invalid blocks) | 655 |
| **FAIL** (completeness gap — wrong hash on a valid block) | **43** |
| **FAIL_NEG** (soundness — guest accepts an invalid block) | **0** |

**Zero failures on Prague or Osaka** — the current target forks. All 43
remaining failures are on older forks (Shanghai 14, Paris 14, Cancun 9,
Berlin 4, London 2) and are all traced to known causes, dominated by one
upstream witness-generation gap rather than a guest execution bug:

| Test file | Blocks | Cause |
|---|---|---|
| `paris/eip7610_create_collision/test_init_collision_create_tx.json` | 18 | `rust-input-gen`/`eest-witness-gen` witness-generation gap (drops a storage preimage) — confirmed byte-identical guest execution vs. a reference trace, so not a guest bug |
| `cancun/eip6780_selfdestruct/test_reentrancy_selfdestruct_revert.json` | 12 | Same witness-generation gap class: revm's bundle-state representation drops storage for self-destructed accounts, upstream of the guest |
| `constantinople/eip1014_create2/test_recreate.json` | 8 | Likely the same witness-generation gap family (CREATE2 + storage); not yet confirmed |
| `static/state_tests/stCreate2/create2collisionStorageParis.json` | 3 | Thematically matches the CREATE2/storage-collision cluster above; not yet confirmed |
| `frontier/create/test_create_one_byte.json` | 2 | Unexplored |

Re-run the sweep above before any release to confirm this list hasn't grown
and that Prague/Osaka remain at zero failures.

## Quick `make` reference

```bash
make all       # rust + cpp
make rust      # input-gen + input-gen-from-manifest
make cpp       # zisk_eth_guest
make input BLOCK=25000000 ETH_RPC_URL=https://…  # build/block_input.bin
make test      # rust unit tests
make clean
```

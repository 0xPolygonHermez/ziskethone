# zisk_eth_guest

A stateless Ethereum block verifier for the [ZisK](https://github.com/0xPolygonHermez/zisk)
RISC-V zkVM, and the stack that proves live blocks with it (EIP-8025 execution proofs).

**Fork targets:**
- **Osaka** (Fusaka, with its BPO blob-parameter forks) is what mainnet runs today.
- **Amsterdam**, the execution half of **Glamsterdam**, has been live on Sepolia since
  2026-10-06. It brings block-level access lists (EIP-7928), the gas repricings, SLOTNUM,
  DUPN / SWAPN / EXCHANGE and more. The guest implements every Amsterdam EIP; see
  [GLAMSTERDAM.md](GLAMSTERDAM.md) for the per-EIP tracker.

Both have zero EEST failures, and so do Cancun and Prague. Older forks are supported well
enough to run the whole EEST corpus. A pre-Cancun edge case that cannot happen on current forks is not fixed when the fix
would complicate the code (see [Current results](#current-results)).

```
┌──────────────────────┐   ZEG0 input   ┌────────────────────────┐
│  rust-input-gen      │ ─────────────▶ │  cpp-guest             │
│  RPC → binary input  │                │  (host binary, or the  │
└──────────────────────┘                │   ZisK ELF)            │
┌──────────────────────┐                │  • re-executes block   │
│  eest-witness-gen    │ ─────────────▶ │  • checks the state    │
│  EEST fixtures →     │                │  • commits 1 public    │
│  inputs (tests)      │                │    output: EIP-8025    │
└──────────────────────┘                │    new_payload_        │
┌──────────────────────┐                │    request_root        │
│  reth-zisk-exex      │ ─────────────▶ └────────────────────────┘
│  live node: input    │      proof (ZisK coordinator)
│  from the BAL, proves├──────────────▶ Lighthouse ──▶ zisk-proof-engine
│  signs, submits      │                (EIP-8025)      (verifies)
└──────────────────────┘
```

The binary input format is in [BINARY_FORMAT.md](BINARY_FORMAT.md). It is designed to be
zero-parse on the guest side: the guest accesses fields through pointer casts to packed
structs.

## Repository layout

| Path | Purpose |
|---|---|
| `cpp-guest/` | The C++ stateless verifier: state DB, MPT, evmone or zevm. `zisk/` builds the ZisK ELF. |
| `rust-input-gen/` | `input-gen` (RPC → input) and `input-gen-from-manifest` (bridge manifest → input). |
| `eest-witness-gen/` | Runs EEST fixtures through reth v2.7.0 and records each block's witness as a manifest. |
| `reth-zisk-exex/` | `reth-zisk`: reth plus an ExEx that proves every new payload and submits the proof. Also `kprove`, a batch prover. |
| `proof-engine/` | `zisk-proof-engine`: the EIP-8025 proof engine Lighthouse calls to verify ZisK proofs. |
| `proof-stats/` | Optional: per-block proof timing, scraped from journald into SQLite. |
| `scripts/` | `eest_sweep.sh`, `killer_sweep.sh` (the test suites), `verify_blocks.py` (follow mainnet), `npr_root_ref.py`. |
| `eest-tests/` | Extra EEST benchmark scenarios written for this guest. |
| `docs/` | Tutorials (live proving on Sepolia) and performance notes. |
| `GLAMSTERDAM.md` | Amsterdam implementation tracker and per-EIP results. |

## Requirements

- Linux x86-64 (the reference host is Ubuntu). macOS works for the host builds; the bridge
  then needs `SDKROOT=$(xcrun --show-sdk-path)` so bindgen finds the system headers.
- Rust (stable) and CMake 3.25+ with a C++20 compiler.
- For the ZisK ELF: xpack `riscv-none-elf-gcc` **14 or 16** on `PATH`, or passed with
  `RISCV_GCC_BIN=<dir>` (see [AGENTS.md](AGENTS.md) for why not 15).
- For `make killer`: `ziskemu` from ZisK 1.4.0 (`ziskup`, or set `ZISKEMU=`).
- For the test suites: `curl`, `jq`, `bc`, `python3`.
- For live blocks: an Ethereum node with the `debug` namespace (`debug_executionWitness`,
  `debug_traceBlockByHash` with `prestateTracer`). A full node keeps state only for recent
  blocks (about the last 32), so verify blocks near the head.

## Building

```bash
make rust            # target/release/input-gen, input-gen-from-manifest
make cpp             # cpp-guest/build/zisk_eth_guest  (host guest, mainnet, evmone)
make elf CHAIN=sepolia EVM_BACKEND=evmone   # the ZisK ELF a prover runs
make exex            # reth-zisk-exex/target/release/reth-zisk (and kprove)
make proof-engine    # proof-engine/target/release/zisk-proof-engine
make help            # every target and variable
```

Build options, all CMake cache variables, one build directory per combination:

| Option | Values | Meaning |
|---|---|---|
| `EVM_BACKEND` | **`evmone`** (default), `zevm` | evmone's baseline interpreter, or the in-tree zevm (`cpp-guest/src/zevm/`), both behind the evmc2 interface. evmone is the deployed backend. |
| `ZEG_CHAIN` | **`mainnet`**, `sepolia` | Chain id, deposit contract and fork schedule compiled into the guest. |
| `ZEG_FORK_FROM_INPUT` | **`OFF`**, `ON` | `ON` takes the fork and blob parameters from the input instead of the chain's schedule. **Tests only**: EEST replays every fork at synthetic times. A deployed ELF must keep it `OFF`. |
| `ZEG_PUBLIC_OUTPUT` | **`npr`**, `block_hash` | The committed output: the EIP-8025 `new_payload_request_root`, or the block hash for consumers outside EIP-8025. |

`make elf` writes `cpp-guest/zisk/build-$(CHAIN)-$(EVM_BACKEND)/zisk_eth_guest.elf`. By hand,
the ELF needs a configured host build for evmone's patched source:

```bash
cmake -S cpp-guest -B cpp-guest/build-sepolia -DZEG_CHAIN=sepolia
cmake -S cpp-guest/zisk -B cpp-guest/zisk/build-sepolia-evmone \
  -DCMAKE_TOOLCHAIN_FILE=$PWD/cpp-guest/zisk/toolchain.cmake -DCMAKE_BUILD_TYPE=Release \
  -DEVM_BACKEND=evmone -DZEG_CHAIN=sepolia \
  -DEVMONE_SRC=$PWD/cpp-guest/build-sepolia/_deps/evmone-src
cmake --build cpp-guest/zisk/build-sepolia-evmone --target zisk_eth_guest.elf -j
```

## Verifying a single block

```bash
RPC=http://localhost:8545
HEAD=$(cast block-number --rpc-url $RPC)
./target/release/input-gen --rpc-url $RPC --block $((HEAD - 3)) --output build/block_input.bin
./cpp-guest/build/zisk_eth_guest build/block_input.bin
```

The host guest prints two lines:
1. The recomputed block hash. It must equal the chain's (`cast block <N> --json | jq -r .hash`).
2. The public output, the EIP-8025 `new_payload_request_root`. This is the SSZ
   `hash_tree_root` of the block's Engine API `NewPayloadRequest`: the payload, blob versioned
   hashes, parent beacon block root and execution requests. It uses the Amsterdam schema for
   every fork, with empty or zero values for the fields a fork lacks.

The ZisK ELF commits only the root. `scripts/npr_root_ref.py` recomputes it with
execution-specs for an independent check.

For a Sepolia block, use a `-DZEG_CHAIN=sepolia` build and the Sepolia node. `input-gen`
picks the fork schedule from the node's chain id.

### Following the chain: `scripts/verify_blocks.py`

It polls a node for new heads and verifies each block as it arrives.

```bash
python3 scripts/verify_blocks.py --rpc-url $RPC --poll-sec 5          # follow the head
python3 scripts/verify_blocks.py --rpc-url $RPC --start-from 25000000 --no-claude
```

- Mid-fetch reorgs: `input-gen` exits with 75 and the block is retried, up to 5 times.
- Any other failure leaves `build/verify/<block>/`, containing `input.bin`, the logs, the
  chain's block and `failure.md`.
- Without `--no-claude`, a failure also opens a `claude` debug session.

## Conformance: `make eest`

```bash
make eest                                   # every EEST blockchain test, evmone backend
make eest EVM_BACKEND=zevm                  # the same with zevm
make eest EEST_PATHS=build/fixtures/eest/fixtures/blockchain_tests/for_amsterdam
make eest EEST_PATHS=build/fixtures/eest/fixtures/blockchain_tests/for_amsterdam/amsterdam/eip7928_block_level_access_lists
```

`make eest` does the following:
1. Downloads the fixtures of the execution-specs release `EEST_RELEASE` (default
   [`tests@v21.0.1`](https://github.com/ethereum/execution-specs/releases/tag/tests%40v21.0.1),
   all forks Frontier to Amsterdam) into `build/fixtures/eest`, once.
2. Builds the bridge and a test guest (`ZEG_FORK_FROM_INPUT=ON`) in
   `cpp-guest/build-test-$(EVM_BACKEND)`.
3. Runs [`scripts/eest_sweep.sh`](scripts/eest_sweep.sh).

For each fixture, the sweep runs `eest-witness-gen`, which executes it on reth and records the
witness. It then runs `input-gen-from-manifest` and the guest on every block, compares the
guest's block hash with the fixture's, and classifies the block. Fixtures are grouped by the
fork they are filled for, `for_<fork>/`. The `for_amsterdam/` tree also re-runs older forks'
tests under Amsterdam rules.

The script prints a tally, overall and per directory, and writes one line per block to
`build/eest-$(EVM_BACKEND)/results.log`. It also runs on its own:
`scripts/eest_sweep.sh [-g GUEST] [-o OUT] [-j JOBS] PATH...`.

The legacy `ethereum/tests` invalid-block suites (`BlockchainTests/InvalidBlocks`, v17.2+) cover
header rules that EEST doesn't: gas-limit bounds, block number, uncles. To run them, pass their
directory in `EEST_PATHS`.

| Category | Meaning |
|---|---|
| `PASS` | A valid block, with the correct hash. |
| `PASS_NEG` | An invalid block (`expect_exception`) the guest rejected: a guest `fatal`, or, for block-level exceptions only, a wrong hash. A crash or timeout is not a rejection. reth refuses such a block, so the bridge gives the guest the block plus a witness of the whole parent state. |
| `FAIL` | **Completeness gap**: a valid block with the wrong hash. |
| `FAIL_NEG` | **Soundness bug**: the guest accepted an invalid block. |
| `FAIL(unsupported_fork)` | A fork the guest doesn't implement. |
| `NA_NEG(rlp_envelope)` | Invalid only in the block's RLP envelope, for example a body without the withdrawals list. The guest input is structured, not block RLP, so there is nothing to reject. The same header with a correctly encoded body is valid. |
| `NA_POS(npr_partial_requests)` | A valid EL block whose modified request predeploy returned a partial request record. No typed EIP-8025 `ExecutionRequests` can hold it, so the block has no `new_payload_request_root`, and the CL could not have built it either. |
| `MISSING` | No result: a network the bridge doesn't support (pre-Berlin), a block reth can't decode, or a bridge failure (`BRIDGE_FAIL`). |

### Current results

`make eest` on [`tests@v21.0.1`](https://github.com/ethereum/execution-specs/releases/tag/tests%40v21.0.1),
the evmone backend, 2026-10-29: 12,272 fixture files and about 134,000 blocks, across all forks and
transitions.

| | Blocks |
|---|---:|
| PASS | 102,663 |
| PASS_NEG (correctly rejected invalid blocks) | 10,819 |
| NA_POS (partial request records, no EIP-8025 root) | 12 |
| **FAIL** (completeness gap: wrong hash on a valid block) | **12** |
| **FAIL_NEG** (soundness: guest accepts an invalid block) | **0** |
| MISSING | 20,657 |

Of the MISSING blocks:
- 20,482 are pre-Berlin forks (Frontier to Istanbul), which the bridge doesn't support.
- The other 175 are invalid blocks reth can't decode, so no guest input exists: bad or
  unrecoverable signatures, full blobs inside the block RLP, a blob or set-code transaction
  that creates a contract, and fork-transition headers missing a field.

**Zero failures on Cancun, Prague, Osaka and Amsterdam**, and on the fork transitions. All 12
failures are on pre-Cancun forks:

| Fixture | Forks | Blocks | Status |
|---|---|---:|---|
| `constantinople/eip1014_create2/recreate/recreate.json` | Berlin, London, Paris, Shanghai | 12 | Pre-Cancun only, won't fix (see below) |

Four Amsterdam `system_contract_errors` blocks (EIP-8282, and EIP-7002 / 7251 under
Amsterdam) also failed. Each injects a system contract larger than the 64 KiB code-size limit
into the pre-state, which the analysis cache couldn't hold. A Paris `opcodes_transaction_init`
block also failed: input-gen labelled every Paris block as London (both have 16 header fields),
so PREVRANDAO returned the difficulty. Input-gen now marks a 16-field header with difficulty 0
as Paris. All five now pass; the numbers above include both fixes.

`recreate`: a contract that existed before the block SELFDESTRUCTs, then the same
address comes back in the same block, because it receives value or is re-created with
CREATE2.
- **What goes wrong:** the destruction wipes the contract's storage, but the guest only zeroes
  the slots the witness names. The new-root pass still hashes the account's block-start storage
  subtree, including slots the block never read, so the revived account gets a stale storage
  root.
- **Why it can't happen on current forks:** since Cancun (EIP-6780), SELFDESTRUCT only destroys
  an account created in the same transaction. EIP-7610 forbids creating at an address that has
  storage.
- **Why it isn't fixed:** a fix would mean rebuilding storage subtrees in the state-root pass,
  which isn't worth it for a case that can't happen on the target forks.

Run `make eest` before a release, and check that Osaka and Amsterdam still have zero failures.

## Prover-killer blocks: `make killer`

```bash
make killer                                 # 200M-gas worst-case blocks, evmone ELF
make killer EVM_BACKEND=zevm
make killer KILLER_GAS=0030M                # the 30M-gas set
```

A prover-killer is a valid block that costs far more to prove than a normal block, or can't be
proven at all, for example because it exhausts the guest's 512 MiB of RAM. The zkevm-benchmark
fixtures (execution-specs release `KILLER_RELEASE`, default
[`tests-zkevm-benchmark@v21.0.5`](https://github.com/ethereum/execution-specs/releases/tag/tests-zkevm-benchmark%40v21.0.5))
fill whole blocks with the worst case of one opcode or precompile: cold account access, SSTORE,
KECCAK, MODEXP, pairing, large RETURNs, deep call chains and so on. They come in
30/60/100/150/200M-gas sets. `make killer` uses the 200M set (`KILLER_GAS=0200M`).

`make killer` does the following:
1. Downloads the set into `build/fixtures/killer-$(KILLER_GAS)`.
2. Builds the test host guest and the **ZisK ELF** (`ZEG_FORK_FROM_INPUT=ON`).
3. Runs [`scripts/killer_sweep.sh`](scripts/killer_sweep.sh):
   - **Phase 1:** each fixture goes through the bridge and the host guest.
   - **Phase 2:** each block runs on the ELF in `ziskemu`, biggest input first,
     `KILLER_JOBS` (4) at a time, because each emulator uses several GB of RAM.

A block **PASSes** when the ELF's output equals the host's `new_payload_request_root` and the
host's block hash equals the fixture's. The others are:
- `EMU_DIFF`: the ELF disagrees with the host.
- `EMU_ERR` / `EMU_TIMEOUT`: the ELF halted, for example out of memory, or ran too long.
- `HASH_MISMATCH`: the ELF and host agree, but the hash is wrong.

The sweep prints a tally and the 20 costliest blocks by steps, and writes
`build/killer-$(KILLER_GAS)-$(EVM_BACKEND)/results.log`. A full 200M run takes several hours.

**Current result (2026-10-29, 200M set):**
- **200M set:** all 2,528 blocks pass on both the evmone and the zevm ELF.
- **30M set:** all 2,514 blocks pass.

The costliest are the cold-account blocks (BALANCE / EXTCODEHASH over ~77k accounts, about
490M steps), which used to exhaust zevm's heap. To prove the inputs on a real ZisK
coordinator rather than emulate them, use `kprove` (`reth-zisk-exex/src/bin/kprove.rs`). It
takes a list of input files and writes a CSV of proving times; stop the live exex first,
because the coordinator runs one program at a time.

## Live proving and deployment (Sepolia)

The live stack proves every Sepolia block with ZisK and publishes the proofs over the
beacon network:

```
Lighthouse ──newPayload──▶ reth-zisk (reth v2.7.0 + ExEx) ──input──▶ ZisK coordinator + GPU workers
    ▲                           │ sign (validator key), POST            │ proof
    │                           ▼                                       │
    └── /eth/v1/beacon/execution_proofs ◀──────────────────────────────┘
Lighthouse ──verify──▶ zisk-proof-engine (pinned program VK) ──▶ gossip `execution_proof`
```

- **`reth-zisk`** ([reth-zisk-exex/](reth-zisk-exex/README.md)) runs in place of the Sepolia
  reth, on the same datadir and ports. For each newPayload:
  - It builds the guest input from the block access list before reth finishes executing,
    and starts proving about 300 ms after the payload arrives.
  - It proves the input on the coordinator. A newer block cancels the running job.
  - It signs an `ExecutionProofEnvelope` with an active validator key and POSTs it to
    Lighthouse.
- **`zisk-proof-engine`** ([proof-engine/](proof-engine/README.md)) answers Lighthouse's
  `--proof-engine-endpoint` calls. It verifies each proof against the pinned **program VK**
  of the guest ELF and the coordinator's **setup VK**.
- **Lighthouse** must be `unstable` at commit `16ce0a072` or later.
- **The ZisK coordinator** and its GPU workers (ZisK 1.4.0, proving key installed) run on a
  separate prover host.
- **`proof-stats`** ([proof-stats/](proof-stats/README.md)) is optional and records the
  per-stage timing.

The full walkthrough, with Lighthouse, keys and the coordinator, is in
[docs/tutorial-prove-and-submit.md](docs/tutorial-prove-and-submit.md). A beacon node that
follows the chain on proofs alone, with no execution client, is in
[docs/tutorial-lighthouse-without-el.md](docs/tutorial-lighthouse-without-el.md).

### Build and install

```bash
make elf CHAIN=sepolia          # cpp-guest/zisk/build-sepolia-evmone/zisk_eth_guest.elf
make exex proof-engine
```

The reference deployment uses this layout, with `$Z` for the data directory, for example
`~/data/zisk`:

| Path | Content |
|---|---|
| `/usr/local/bin/reth-zisk`, `/usr/local/bin/zisk-proof-engine` | The binaries. Keep the previous ones as `.bak-<date>` for rollback. |
| `$Z/guest/<date>-<commit>-<tag>/zisk_eth_guest.elf` | One directory per deployed ELF. |
| `$Z/guest/current` | Symlink to the deployed ELF's directory. |
| `$Z/etc/reth-zisk.env` | `ZISK_COORDINATOR=http://<prover>:7000`, `ZISK_EXTRA_ARGS=--zisk.submit` |
| `$Z/etc/proof-engine.env` | `PE_CHAIN_ID`, `PE_PROGRAM_VK`, `PE_SETUP_VK`, `PE_EXTRA_ARGS` |
| `$Z/keys/` | The validator `keystore.json` and `password.txt`. |
| `$Z/proofs/` | Per-block output, plus `program_vk.hex`. |

The two systemd units, reduced to what matters. The reth flags are the same as
`reth-sepolia.service`'s:

```ini
# /etc/systemd/system/reth-zisk-sepolia.service
[Unit]
Conflicts=reth-sepolia.service          # same datadir: only one of the two runs
[Service]
EnvironmentFile=$Z/etc/reth-zisk.env
ExecStart=/usr/local/bin/reth-zisk node --chain sepolia --datadir <reth-sepolia datadir> \
    <reth-sepolia's flags: ports, --authrpc.*, --http.api ...,debug,...> \
    --zisk.mode prove --zisk.out-dir $Z/proofs \
    --zisk.elf $Z/guest/current/zisk_eth_guest.elf \
    --zisk.coordinator ${ZISK_COORDINATOR} --zisk.beacon-url http://127.0.0.1:5053 \
    --zisk.keystore $Z/keys/keystore.json --zisk.keystore-password-file $Z/keys/password.txt \
    $ZISK_EXTRA_ARGS
Restart=always
TimeoutStopSec=600

# /etc/systemd/system/zisk-proof-engine.service
[Service]
EnvironmentFile=$Z/etc/proof-engine.env
ExecStart=/usr/local/bin/zisk-proof-engine serve --listen 127.0.0.1:9551 \
    --chain-id ${PE_CHAIN_ID} --program-vk ${PE_PROGRAM_VK} --setup-vk ${PE_SETUP_VK} $PE_EXTRA_ARGS
Restart=always
```

Lighthouse is then started with `--proof-engine-endpoint http://127.0.0.1:9551`.

### Upgrading the guest ELF

Every change to the guest, its build flags, or the ZisK version produces a new **program
VK**. Every proof engine that verifies the proofs must pin it, including remote nodes that
receive the proofs over gossip. The exex mints the VK, so the steps go in this order:

1. **Check before deploying.**
   - Run `make killer` and `make eest` on the new code.
   - Run the host guest and the ELF on a few recent Sepolia blocks (`input-gen` on blocks
     near the head). Both must give the chain's hash and the same root.
2. **Install.**
   - Copy the ELF to a new `$Z/guest/<date>-<commit>-<tag>/` directory.
   - Point `$Z/guest/current` at it.
   - Install the new binaries if they changed, keeping the `.bak` copies.
3. **Restart the exex.** `sudo systemctl restart reth-zisk-sepolia`. At startup it registers
   the ELF with the coordinator, runs the setup, and writes `$Z/proofs/program_vk.hex`.
4. **Re-pin the VK.**
   - Set `PE_PROGRAM_VK` to that value in every proof engine's env file, and restart them.
   - To switch over with no gap, pass the old VK as a second `--program-vk` in
     `PE_EXTRA_ARGS` for a while.
5. **Watch the first blocks.** Check that `status.json` reaches `submitted` and the proof
   engine logs `VALID`. The exex only proves once reth is at the chain head; while catching up
   it cancels each job.

To roll back, point `current` at the previous directory, restore the binaries, restart the
exex, and re-pin the old VK.

Things to keep in mind:
- **One program at a time.** The coordinator keeps one active program. Any other client
  that runs a setup (`kprove`, a test) displaces the exex's ELF, so stop
  `reth-zisk-sepolia` first and restart it after.
- **The proof layout is hand-copied.** `proof-engine/src/proof.rs` mirrors ZisK's `Proof`
  bincode layout by hand. When the ZisK version changes, re-check its field order, or every
  proof fails as trailing bytes.
- **The setup VK changes with the proving key.** If the coordinator regenerates its proving
  key, re-pin `PE_SETUP_VK`, using the raw 32 bytes of
  `vadcop_final/vadcop_final.verkey.bin`.
- **Pausing.** To stop proving, stop `reth-zisk-sepolia` and start `reth-sepolia`, on the same
  datadir.

## Quick `make` reference

| Target | Does |
|---|---|
| `make all` / `rust` / `cpp` | Host tools, and the mainnet evmone host guest in `cpp-guest/build`. |
| `make input BLOCK=N` | `build/block_input.bin` from the RPC. |
| `make test` | Rust unit tests. |
| `make elf [CHAIN=] [EVM_BACKEND=]` | The deployable ZisK ELF. |
| `make exex` / `proof-engine` / `bridge` | Builds those crates. |
| `make guest-test` / `elf-test` | Host guest and ELF with `ZEG_FORK_FROM_INPUT=ON`. |
| `make eest [EEST_PATHS=]` | The EEST conformance sweep. |
| `make killer [KILLER_GAS=] [KILLER_PATHS=]` | The prover-killer sweep on the ELF. |
| `make help` | Lists the variables: `EVM_BACKEND`, `CHAIN`, `JOBS`, `KILLER_JOBS`, `FIXTURES`, `ZISKEMU`, `RISCV_GCC_BIN`. |

## License

All code in this repository is licensed under one of the following options:

- The Apache License, Version 2.0 (see LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)

- The MIT License (see LICENSE-MIT or http://opensource.org/licenses/MIT)

You may choose either license at your discretion.

# ziskethone — guidance for Claude

## Fork targets

- **Mainnet runs Osaka** (Fusaka, plus its BPO blob-parameter forks).
- **Sepolia runs Amsterdam**, the execution half of Glamsterdam, since 2026-10-06. The guest
  implements every Amsterdam EIP; [GLAMSTERDAM.md](GLAMSTERDAM.md) tracks them.
- Both must stay at **zero EEST failures**.
- Older forks only need to run the EEST corpus. A pre-Cancun-only edge case that needs a
  complex fix is documented in the README rather than fixed.

## Block verification / witnesses

- The local Ethereum RPC is at `http://localhost:8545` (reth).
- The node only serves **state for ~32 recent blocks**. When generating a witness
  with `input-gen` (or any verification that needs state), **never target a block
  more than 32 blocks older than the current head**. Always read the head first
  (`eth_blockNumber`) and pick a block within 32 of it (e.g. `head - 3`).
- A witness for a too-old block fails with "block N not found" / no state.

## Builds

- **Backend:** the guest drives the EVM through the evmc2 interface. The backend is the
  `EVM_BACKEND` CMake option: `evmone`, the default and the deployed one, or `zevm`.
- **Chain:** `ZEG_CHAIN` is `mainnet` (default) or `sepolia`. It sets the chain id, the deposit
  contract and the fork schedule.
- **Fork source:** `ZEG_FORK_FROM_INPUT=ON` takes the fork from the input. It is **for test
  builds only**, because EEST replays every fork at synthetic times. A deployed ELF must keep
  it OFF; with OFF, EEST inputs fail.
- **One build dir per combination** (the options are cached):
  - `cmake -S cpp-guest -B cpp-guest/build      -DEVM_BACKEND=evmone` → `build/zisk_eth_guest`
  - `cmake -S cpp-guest -B cpp-guest/build-zevm -DEVM_BACKEND=zevm`   → `build-zevm/zisk_eth_guest`
  - `make guest-test` / `make elf-test` → `cpp-guest/build-test-<backend>` and
    `cpp-guest/zisk/build-test-<backend>`, with FORK_FROM_INPUT=ON
  - `make elf CHAIN=sepolia` → `cpp-guest/zisk/build-sepolia-<backend>/zisk_eth_guest.elf`,
    the deployable ELF
- **evmone patches:** `cpp-guest/patches/*.patch` are applied when the host build is
  configured. Configure checks the whole stack and resets and re-patches `_deps/evmone-src`
  when it differs, so a new or edited patch just needs a reconfigure. Hand edits in
  `_deps/evmone-src` are lost.
- **ELF and evmone source:** the ELF reuses a host build's evmone source (`-DEVMONE_SRC=…`;
  the Make targets pass it).

## Test suites

- **`make eest`**: the EEST conformance sweep (`scripts/eest_sweep.sh`).
  - It downloads `tests@v21.0.1` once into `build/fixtures/eest`, then checks every block's
    hash.
  - Results go to `build/eest-<backend>/results.log`.
  - Narrow it with `EEST_PATHS=…/for_amsterdam/amsterdam/<eip dir>`.
  - `FAIL_NEG` (accepted an invalid block) is a soundness bug. `FAIL` is a completeness gap.
- **`make killer`**: the prover-killer sweep (`scripts/killer_sweep.sh`).
  - It runs the zkevm-benchmark 200M-gas worst-case blocks (`tests-zkevm-benchmark@v21.0.5`,
    `KILLER_GAS=0200M`) on the **ZisK ELF in ziskemu**.
  - A block passes when the ELF output equals the host root and the block hash is right.
  - It prints the costliest blocks by steps. Results go to
    `build/killer-0200M-<backend>/results.log`.
  - It needs `ziskemu` (`ZISKEMU=`) and the xpack GCC (`RISCV_GCC_BIN=`).
  - Expected: every block PASSes on both backends.
- **Common variables:** `EVM_BACKEND=zevm` runs either suite on zevm. `JOBS` and
  `KILLER_JOBS` (default 4) set the parallelism.
- **Memory:** ziskemu and the bridge are RAM-heavy. With the nodes running (about 20 GB of
  30 GB), keep the job counts low, or run them under
  `systemd-run --user --scope -p MemoryMax=…` so an OOM can't take down the nodes.
- **Comparing step counts:** the bridge regenerates inputs with different bytes (a fresh
  hash seed) on every run, which moves steps by up to ±45%. Compare steps only on identical
  input files.

## Guest memory (ZisK ELF)

- **Layout:** 512 MiB of RAM minus a 4 MiB stack. The heap is whatever the static data leaves.
- **Allocator:** a bump allocator that never frees (`zisk/runtime.cpp`), plus a
  per-transaction arena (`zeg/tx_arena.hpp`) that is reset at each transaction start.
- **Heap per backend:** evmone has about 407 MiB of heap. zevm has about 259 MiB, because its
  EVMMem zones and frame stacks are static.
- **Measuring:** configure the ELF with `-DZEG_HEAP_STATS=ON` to print per-phase heap use.
- **When a valid block fails:** an EMU_ERR on a block the host guest passes is usually heap
  exhaustion.

## RISC-V ELF cross-compiler

Build the ZisK guest ELF (`cpp-guest/zisk`) with GCC **14 or 16** (xpack
`riscv-none-elf-gcc`). Ubuntu's `riscv64-unknown-elf-g++` 13.2.0 ships no libstdc++
headers, so it can't build the C++ guest. Put the cross `bin/` on `PATH`;
`toolchain.cmake` auto-detects the prefix.

History/caveat: GCC **15.2.0 and 16.1.0 miscompiled** an earlier *index-based* stack
(`s.stack[sp]` with a 64-bit `sp`) → wrong block-state root (a GCC RISC-V wrong-code
regression, not a zevm bug; cf. GCC bugzilla PR123050; host g++13 + UBSan/ASan + full
EEST were clean, only GCC 14 codegen was correct). The **pointer-to-top stack**
(commit `fbb34e7`, `Regs::top`) generates a different addressing pattern and builds
correctly on GCC 14 *and* 16, so the bug no longer bites. If you ever reintroduce a
miscompile (ELF hash wrong — e.g. starts `0xaaaa…` — while the host build + EEST pass),
suspect the toolchain and drop to GCC 14.

## Verify a single block

```bash
HEAD=$(curl -s -X POST http://localhost:8545 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | grep -o '0x[0-9a-f]*')
BLK=$(( HEAD - 3 ))
./target/release/input-gen --rpc-url http://localhost:8545 --block $BLK --output build/block_input.bin
./cpp-guest/build-zevm/zisk_eth_guest build/block_input.bin | tail -1   # must match:
./cpp-guest/build/zisk_eth_guest     build/block_input.bin | tail -1
```

The host guest prints the recomputed block hash (line 1, must equal the chain's
`hash`) and then the public output, the EIP-8025 `new_payload_request_root`
(the last line; the only output of the ZisK ELF). `scripts/npr_root_ref.py`
recomputes the root with execution-specs for an independent check.

`input-gen` calls `debug_executionWitness` and `debug_traceBlockByHash`
(prestateTracer): reth's witness `keys` omit accounts that were loaded but don't
exist, and every loaded key must be a leaf in the input — the guest halts on any
other ("state key not in witness").

## Sepolia

Use separate build dirs for the Sepolia chain:

```bash
cmake -S cpp-guest -B cpp-guest/build-sepolia      -DEVM_BACKEND=evmone -DZEG_CHAIN=sepolia
cmake -S cpp-guest -B cpp-guest/build-zevm-sepolia -DEVM_BACKEND=zevm   -DZEG_CHAIN=sepolia
```

`input-gen` picks the fork schedule from the node's chain id. It needs a Sepolia
reth node with the `debug` namespace (public endpoints such as publicnode
don't serve `debug_executionWitness`); the same 32-block rule applies. A local
Sepolia reth node serves it at `http://127.0.0.1:8645`.

## Live prover (`reth-zisk-exex/`)

`reth-zisk` is reth v2.7.0 plus an ExEx. For every newPayload it does the following:
- It builds the ZEG0 input in-process. With the block access list (Amsterdam), it builds it
  before reth finishes executing; without one, it re-executes the block.
- It proves the input on the ZisK coordinator, or runs ziskemu in `--zisk.mode emulate`. A
  newer block cancels the running job.
- It signs and POSTs the EIP-8025 proof to Lighthouse.

How it runs and builds:
- It runs as `reth-zisk-sepolia.service` in place of `reth-sepolia.service`, on the same
  datadir. The units conflict, so only one of the two runs.
- It has its own `Cargo.lock`. Build it with `make exex` or `cargo build --release` inside the
  directory.
- The extra `kprove` bin proves a list of input files on the coordinator and writes a CSV.
- See `reth-zisk-exex/README.md` and the README's "Live proving and deployment" section.

## Proof engine (`proof-engine/`)

`zisk-proof-engine` is the EIP-8025 ProofEngine that Lighthouse calls through
`--proof-engine-endpoint` (`POST /v1/execution_proof_verifications`).
- It verifies the exex's VadcopFinal proofs with `zisk-verifier`, pinned to the same ZisK rev
  as the prover (1.4.0-alpha).
- It checks each proof against the pinned **program VK** (`program_vk.hex` from the exex)
  and the proving key's vadcop_final **setup VK**.
- It binds the committed 32-byte root to the query's `new_payload_request_root`.
- `proof-engine/src/proof.rs` copies ZisK's `Proof` bincode layout by hand. Re-check it
  whenever the ZisK version changes.
- It is a standalone crate with its own lock file: `make proof-engine`.

## Deployment (Sepolia prover)

The procedure is in the README ("Upgrading the guest ELF"). The rules:
- **Every guest or build change produces a new program VK.** Deploy in this order:
  1. Install the ELF in a new `guest/<date>-<commit>-<tag>/` dir and point `guest/current`
     at it.
  2. Restart `reth-zisk-sepolia`. At setup it writes `proofs/program_vk.hex`.
  3. Set `PE_PROGRAM_VK` on **every** proof engine, local and remote, and restart them.
- **Before deploying:** `make killer` and `make eest` must pass. The host guest and the ELF
  must agree on recent Sepolia blocks.
- **The coordinator runs one program at a time.** Stop `reth-zisk-sepolia` before using the
  coordinator for anything else (`kprove`, tests), and restart it afterwards.
- **Ask first.** Deploying, restarting services, or touching the live nodes always needs the
  user's go-ahead.

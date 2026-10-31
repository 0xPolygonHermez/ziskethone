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
  it OFF; with OFF, EEST inputs fail. With OFF the input's `fork_id` must also equal the
  schedule's fork for the block's timestamp (input-gen and the exex write it from the same
  schedule), or the guest halts.
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
- **`make unit`**: host unit tests for the guest's memory-discipline building blocks
  (`cpp-guest/test/*_test.cpp`: ChunkedVector, the tx arena / FrameScratch, the seeded hash,
  Contracts staging, state-root ChainNode folding). `make unit SANITIZE=1` runs them under
  ASan+UBSan. Also run by `make test`.
- **`make heap-gate CHAIN=mainnet`**: the heap regression gate (`scripts/heap_gate.py`, see
  [HEAP_BUDGET.md](HEAP_BUDGET.md)). It runs the heaviest killer blocks
  (`scripts/heap_gate/blocks-0200M.txt`) on a heap-stats ELF (`make heap-elf`) with a pinned
  seed, and fails if any block's heap or arena use regresses past its baseline
  (`scripts/heap_gate/baseline-0200M-<backend>.tsv`), past the modeled bound
  (`scripts/heap_bound.py` over `scripts/heap_gate/sites.tsv`), or past 60% of the ELF heap.
  `HEAP_GATE_UPDATE=1` rewrites the baseline for an intended change — commit the new TSV with
  the code change and quote the per-block deltas it prints. If a `// heap-budget:`
  `static_assert` trips, a per-node size moved: update `sites.tsv` (and so HEAP_BUDGET.md,
  which `heap_bound.py --self-check` keeps in sync).
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
  per-transaction arena (`zeg/tx_arena.hpp`) that is reset at each transaction and system-call
  start (`ZiskStateDB::reset_tx_arena`).
  - **In the arena:** the journal, transient storage, evmone's EVM memory (patch 16; the VM
    drops it through `release_tx_buffers` before the reset), CREATE init-code analyses
    (evmone's in a LIFO `FrameScratch`, handed back when the frame returns), and the code a
    transaction deploys: `Contracts::settle_staged` moves the code that survived to the heap
    at the next reset and forgets the rest.
  - **Views, no copies:** call outputs and `return_data` point into the callee's memory, so
    anything kept past the next call at that depth must be copied (deployed code, requests).
  - **Arena memory is not zero** once reused: initialise what you allocate.
  - **No doubling vectors for data that grows with gas:** a `std::vector` leaves every buffer
    it outgrew behind. Use `zeg::ChunkedVector` (the journal, receipt logs, the state-root
    node arrays) or reserve the exact count (BAL slots, receipts). evmone's EVM memory
    recycles outgrown buffers through free lists (patch 16).
- **Heap per backend:** evmone has about 407 MiB of heap. zevm has about 259 MiB, because its
  EVMMem zones and frame stacks are static.
- **Measuring:** `make heap-elf` builds a heap-stats ELF (`-DZEG_HEAP_STATS=ON`) that prints
  per-phase `HEAP` lines and a per-block `HEAP block` line. [HEAP_BUDGET.md](HEAP_BUDGET.md)
  turns these into a worst-case bound checked by `make heap-gate`; `scripts/heap_bound.py`
  computes the bound and `--self-check`s the doc, the `static_assert`s and the citations.
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
- **Before deploying:** `make killer`, `make eest` and `make heap-gate CHAIN=mainnet` must
  pass (the last on both backends: `EVM_BACKEND=evmone` and `=zevm`). The host guest and the
  ELF must agree on recent Sepolia blocks.
- **Build stamp:** build the deployed ELF with `make elf`. It carries `ZEG_BUILD_FLAGS:`, and
  the exex refuses an ELF without a deploy stamp for its chain.
- **The coordinator runs one program at a time.** Stop `reth-zisk-sepolia` before using the
  coordinator for anything else (`kprove`, tests), and restart it afterwards.
- **Ask first.** Deploying, restarting services, or touching the live nodes always needs the
  user's go-ahead.

### Computing the program VK offline (coordinator down)

Normally the exex mints the program VK at coordinator setup (writes `proofs/program_vk.hex`).
When the coordinator is unreachable you can still deploy: the VK is the guest ROM's
custom-commit Merkle root, deterministic from the ELF and **proving-key independent** (blake3,
blowup factor 2, Merkle arity 2), so compute it offline and deploy **without starting the exex**.

A tiny crate does it. Keep it in your scratchpad and rebuild it against the **local ZisK
checkout at the prover's version tag** (`git -C ~/git/zisk describe --tags` must be e.g.
`v1.4.0-alpha`) — the `CustomRom::build` / `write_custom_commit_c` API tracks the ZisK/proofman
release, so a version bump may need the crate adjusted.

`progvk/Cargo.toml`:

```toml
[package]
name = "progvk"
version = "0.1.0"
edition = "2021"
[dependencies]
zisk-sm-rom = { path = "/home/jbaylina/git/zisk/state-machines/rom" }
zisk-common = { path = "/home/jbaylina/git/zisk/common" }
proofman-common       = "1.4.0-alpha"
proofman-fields       = "1.4.0-alpha"
proofman-starks-lib-c = "1.4.0-alpha"
```

`progvk/src/main.rs`:

```rust
use proofman_common::trace::Trace;
use proofman_fields::Goldilocks;
use zisk_common::HashMode;
use zisk_sm_rom::CustomRom;

fn main() {
    let elf = std::fs::read(std::env::args().nth(1).expect("usage: progvk <elf>")).unwrap();
    let mode = HashMode::Blake3;
    proofman_starks_lib_c::set_hash_family_c("blake3"); // as GlobalInfo does for a blake3 key
    let mut trace = CustomRom::build::<Goldilocks>(&elf).expect("building the ROM trace");
    let (n, n_cols) = (trace.num_rows() as u64, trace.num_cols() as u64);
    let n_ext = mode.blowup_factor() * n;
    let mut root = [0u64; 4];
    let buf: Vec<Goldilocks> = Trace::<Goldilocks>::get_buffer(&mut trace);
    proofman_starks_lib_c::write_custom_commit_c(
        root.as_mut_ptr() as *mut u8, mode.merkle_tree_arity(),
        n.trailing_zeros() as u64, n_ext.trailing_zeros() as u64, n_cols,
        std::ptr::null_mut(), buf.as_ptr() as *mut u8, ""); // no cache file; only the root
    const MOD: u64 = 0xFFFF_FFFF_0000_0001; // Goldilocks modulus; reduce to canonical form
    let bytes: Vec<u8> = root.iter().flat_map(|x| (x % MOD).to_le_bytes()).collect();
    println!("0x{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
}
```

Run it — **always validate first** by reproducing the live VK of the currently deployed ELF,
only then trust it for the new one:

```bash
cargo build --release --manifest-path progvk/Cargo.toml
# VALIDATE: this must equal the contents of $Z/proofs/program_vk.hex
./target/release/progvk $Z/guest/current/zisk_eth_guest.elf
# the new ELF's VK:
./target/release/progvk cpp-guest/zisk/build-sepolia-evmone/zisk_eth_guest.elf
```

Then deploy with the exex stopped: stage the ELF and repoint `$Z/guest/current`, write the VK to
`$Z/proofs/program_vk.hex`, set `PE_PROGRAM_VK` on **every** proof engine (local and remote) —
keep `PE_SETUP_VK` (the proving key's `vadcop_final.verkey.bin`) unchanged unless the key itself
changed — and restart the PEs. When the coordinator returns, start the exex and confirm the VK it
mints equals the computed one (it will, being deterministic) and a fresh proof's setup VK matches;
re-pin if either differs.

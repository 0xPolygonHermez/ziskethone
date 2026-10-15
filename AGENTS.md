# ziskethone — guidance for Claude

## Block verification / witnesses

- The local Ethereum RPC is at `http://localhost:8545` (reth).
- The node only serves **state for ~32 recent blocks**. When generating a witness
  with `input-gen` (or any verification that needs state), **never target a block
  more than 32 blocks older than the current head**. Always read the head first
  (`eth_blockNumber`) and pick a block within 32 of it (e.g. `head - 3`).
- A witness for a too-old block fails with "block N not found" / no state.

## EVM backends

- The guest drives the EVM through the evmc2 interface; the backend is a build-time
  choice via the `EVM_BACKEND` CMake option (`evmone` default, or `zevm`). Use a
  separate build dir per backend:
  - `cmake -S cpp-guest -B cpp-guest/build      -DEVM_BACKEND=evmone` → `build/zisk_eth_guest`
  - `cmake -S cpp-guest -B cpp-guest/build-zevm -DEVM_BACKEND=zevm`   → `build-zevm/zisk_eth_guest`

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

The chain is a build-time choice (`ZEG_CHAIN`, default `mainnet`): chain id and
deposit contract. Use separate build dirs:

```bash
cmake -S cpp-guest -B cpp-guest/build-sepolia      -DEVM_BACKEND=evmone -DZEG_CHAIN=sepolia
cmake -S cpp-guest -B cpp-guest/build-zevm-sepolia -DEVM_BACKEND=zevm   -DZEG_CHAIN=sepolia
```

`input-gen` picks the fork schedule from the node's chain id. It needs a Sepolia
reth node with the `debug` namespace (public endpoints such as publicnode
don't serve `debug_executionWitness`); the same 32-block rule applies. A local
Sepolia reth node serves it at `http://127.0.0.1:8645`.

## Live prover (`reth-zisk-exex/`)

`reth-zisk` is reth v2.7.0 plus an ExEx: for every block the engine executes
from a newPayload it builds the ZEG0 input in-process (same bytes as
`input-gen`), pre-checks it with the host guest, proves it (ZisK coordinator,
or ziskemu in `--zisk.mode emulate`) and signs/submits the EIP-8025 proof.
It runs in place of `reth-sepolia.service` on the same datadir (stop the
service first, restart it afterwards). Its own `Cargo.lock`; build with
`cargo build --release` inside the directory. See `reth-zisk-exex/README.md`.

## Proof engine (`proof-engine/`)

`zisk-proof-engine` is the EIP-8025 ProofEngine that Lighthouse calls through
`--proof-engine-endpoint`, using `POST /v1/execution_proof_verifications`. It
verifies the exex's VadcopFinal proofs with `zisk-verifier` (git tag
v1.3.2-alpha, which must match the prover's release). It checks the proof
against a pinned program VK (`program_vk.hex` from the exex) and the proving
key's vadcop_final setup VK, and binds the committed 32-byte root to the query's
`new_payload_request_root`. It is a standalone crate with its own lock file:
`cargo build --release` inside the directory. See `proof-engine/README.md`.

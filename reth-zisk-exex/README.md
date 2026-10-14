# reth-zisk-exex

`reth-zisk` is a reth v2.7.0 node with an execution extension. For each block that arrives by `engine_newPayload`, the node:

1. **Takes the payload at t0.** The engine tree's payload validator is wrapped (`src/tap.rs`): as soon as reth decodes a newPayload, before executing it, a copy of the block and its block access list goes to the prover pipeline.
2. **Builds the ZEG0 guest input from the BAL, without executing** (`witness::sources_from_bal`).
   - The EIP-7928 BAL names every account and slot the block touches, together with the post-values. The guest rebuilds the BAL from its own accesses and checks its hash, so the BAL is exactly the set of keys it loads.
   - The pre-state of those keys is read from the parent state. The trie proofs come from the same `StateProofProvider::witness` that `debug_executionWitness` uses, with the post-state built from the BAL. Codes are those of every BAL account (in practice all used); ancestors are only the parent.
   - On a cold page cache the first proof walk over a block's keys is I/O-bound: 0.5–2.5 s sequential, about 70 ms warm. So 16 threads first read and prove a share of the accounts each, warming the pages, and then the full proof runs.
   - Blocks without a BAL (pre-Amsterdam, mainnet today) are re-executed instead (`witness::sources_by_execution`).
3. **Proves it right away while pre-checking it natively.** The host build of the guest (`zisk_eth_guest`, in a subprocess because a guest fatal is `abort()`) runs alongside the prover. It must recompute the block hash, and its second line is the expected public output, the EIP-8025 `new_payload_request_root`. With `ZEG_DUMP_USED` it also reports the codes and BLOCKHASH ancestors the block used.
   - If the pre-check fails, or the block reads an ancestor beyond the parent (rare), the proof is cancelled and redone on a checked input: BAL with all 256 ancestors, trimmed to the used ones, or re-execution if that also fails.
   - The prover is a ZisK coordinator over gRPC: register and set up the ELF once, then `JobRequest(Prove)`, then `WaitJobResult`. The proof must carry the pre-check root as its public output.
4. **Cancels on a different block.** If a different payload arrives (same or higher number), the engine reports the block invalid, or the in-flight block leaves the canonical chain before its proof is ready, the job is cancelled (`CancelJob`) and the new block starts.
5. **Signs and submits.** It finds the beacon block whose payload bid commits to the block: under Gloas that is the block at the header's `slot_number`. It signs an `ExecutionProofEnvelope` with a validator key and POSTs it to the beacon node. This is the idea of dapplion/proof_seeder, done in-process.

Measured on Sepolia over 10 blocks, in ms from reth receiving newPayload (medians, emulate mode):

| | re-execution after reth's event | BAL, pre-check before proving | BAL, prove while pre-checking (current) |
|---|---:|---:|---:|
| input start | 79 | 2 | 3 |
| input built | 852 | 365 | 286 |
| prove start | 977 | 497 | 304 |

**Taking payloads from Lighthouse directly** (`--zisk.lighthouse-early`: its `execution_payload_gossip` SSE event, then `GET /eth/v1/beacon/execution_payload_envelopes/{root}`) gains nothing:
- the gossip event arrives only 2–6 ms before Lighthouse's newPayload reaches reth;
- the envelope isn't served until Lighthouse has imported the payload, after the EL has executed it (≈ +100 ms).

The flag stays as a second source: the first one wins.

The guest commits only the 32-byte `new_payload_request_root`. The ExEx supplies the rest of the EIP-8025 `PublicInput`:
- `successful_validation = true`, since the guest halts on an invalid block;
- `chain_id`, the beacon spec's `DEPOSIT_CHAIN_ID`, which is checked against the EL chain id at startup;
- `schema_id = 0x1501`.

It writes the `PublicInput` and its `hash_tree_root` to `public_input.json`. The signed envelope (consensus-specs eip8025) does not carry the public input, because the beacon node derives it from its own copy of the payload.

## Build

```bash
cd reth-zisk-exex && cargo build --release      # → target/release/reth-zisk
```
- Rustc 1.95.
- `.cargo/config.toml` makes Cargo resolve to versions that support rustc 1.95, because vergen 10.0.3 (pulled by reth) needs rustc 1.96. The repo does not commit `Cargo.lock` files.
- The crate is not a member of the root workspace.
- `protoc` is needed for the coordinator client in `proto/`, which is vendored from ZisK v1.3.2-alpha.

The pre-check and the prover need the guest built **for the node's chain**:
```bash
cmake -S cpp-guest -B cpp-guest/build-sepolia -DEVM_BACKEND=evmone -DZEG_CHAIN=sepolia
cmake --build cpp-guest/build-sepolia -j
# ZisK ELF (xpack GCC 14 on PATH, see AGENTS.md)
cmake -S cpp-guest/zisk -B cpp-guest/zisk/build-npr-sep-evmone -DEVM_BACKEND=evmone -DZEG_CHAIN=sepolia \
      -DCMAKE_TOOLCHAIN_FILE=$PWD/cpp-guest/zisk/toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build cpp-guest/zisk/build-npr-sep-evmone --target zisk_eth_guest.elf -j
```

## Run

`reth-zisk node` takes every `reth node` flag plus the `--zisk.*` flags below. To use it, run it in place of the node's reth with the same datadir and flags:
```bash
sudo systemctl stop reth-sepolia.service
./reth-zisk-exex/target/release/reth-zisk node --chain sepolia --full ... (the unit's flags) \
    --zisk.mode prove --zisk.out-dir /data/zisk-proofs \
    --zisk.guest-host cpp-guest/build-sepolia/zisk_eth_guest \
    --zisk.elf cpp-guest/zisk/build-npr-sep-evmone/zisk_eth_guest.elf \
    --zisk.coordinator http://prover-host:8000 \
    --zisk.beacon-url http://127.0.0.1:5053 \
    --zisk.keystore keystore.json --zisk.keystore-password-file password.txt \
    --zisk.proof-type 3 --zisk.submit
```

| `--zisk.mode` | Per block |
|---|---|
| `witness` (default) | Input plus native pre-check |
| `emulate` | The same, plus ziskemu (`--zisk.ziskemu`). Checks that the ELF's public output equals the pre-check root. No proof and no submission; for hosts without a GPU. |
| `prove` | The same, plus a coordinator proof, the beacon root, signing, and the POST when `--zisk.submit` is set |

Each block leaves `--zisk.out-dir/<number>-<hash prefix>/`, containing:
- `input.bin`
- `input.exec.bin`, the re-execution input, with `--zisk.compare-exec`
- `public_input.json`
- `proof.bin`
- `signed.ssz`, the SSZ list body as POSTed
- `status.json`: `prechecked`, `emulated`, `signed`, `submitted`, `cancelled` or `failed` with the error

### Prover: ZisK coordinator

Run `zisk-coordinator` with one or more GPU `zisk-worker`s (ZisK `distributed/`, v1.3.2-alpha), with the proving keys installed (`ziskup --provingkey`). At startup the ExEx registers the ELF and runs its setup, then logs the program VK. Proofs are `PROOF_KIND_STARK`: the bincode `zisk_common::Proof` that the coordinator returns, at most `MAX_PROOF_SIZE` = 4 MiB. That byte string is the signed `proof_data`.

### Beacon node

- Submission uses `POST /eth/v1/beacon/execution_proofs` with `application/octet-stream`. The body is the SSZ `ProgressiveList[SignedExecutionProofEnvelope]` (beacon-APIs PR #660).
- Lighthouse serves that endpoint from sigp/lighthouse `unstable` >= 16ce0a0728, started with `--proof-engine-endpoint`. Without a proof engine the route returns 404.
- The signing domain is `DOMAIN_EXECUTION_PROOF` (`0x0F000000`), with the fork version of the referenced block's epoch and `genesis_validators_root`. All three come from `/eth/v1/config/spec` and `/eth/v1/beacon/genesis`.
- The key must be an **active validator**, which is checked at startup. Each `(beacon block, proof_type, validator)` gets one attempt, so the signature is verified locally before it is sent.
- No EIP-8025 `proof_type` is assigned to ZisK yet. Pick the one your proof engine maps to this guest and ELF.

## Tests

`cargo test --release` covers:
- the SSZ roots, domain, signing root and envelope/list encoding, against vectors generated with remerkleable (consensus-specs' SSZ library);
- the BLS signature, against py_ecc;
- the EIP-2335 scrypt and pbkdf2 keystore vectors;
- the `PublicInput` progressive-container root.

# zisk-proof-engine

An EIP-8025 proof engine for the beacon node. It implements
`ProofEngine.verify_execution_proof` (consensus-specs `_features/eip8025/proof-engine.md`)
for the ZisK proofs of `zisk_eth_guest`, which are the proofs `reth-zisk-exex` produces,
signs and submits. Lighthouse calls it through `--proof-engine-endpoint` for every
`SignedExecutionProofEnvelope` it receives, whether over gossip or through
`POST /eth/v1/beacon/execution_proofs`.

## API

This is the wire format of Lighthouse's `beacon_node/proof_engine` client, which is the same as
the dapplion/eth_proof_verifier sidecar. It is plain HTTP with no JWT, and Lighthouse waits at
most 5 s for an answer.

```
POST /v1/execution_proof_verifications?new_payload_request_root=0x..&successful_validation=true
     &chain_id=<u64>&schema_id=<u16>&proof_type=<u8>
  body: raw proof_data (application/octet-stream)
  200 {"status":"VALID"} | 200 {"status":"INVALID","reason":"..."}
  400 {"error":"..."}     malformed query or unsupported proof_type
GET  /v1/proof_types  ->  {"proof_types":[6]}
```

## What is checked

`proof_data` is the bincode `zisk_common::Proof` that the ZisK coordinator returns
(`PROOF_KIND_STARK`, a VadcopFinal STARK). It must satisfy all of the following:

- `successful_validation == true`, `chain_id == --chain-id` and `schema_id == 0x1501`. The guest
  commits only the 32-byte `new_payload_request_root`, so these three fields are bound by
  configuration:
  - The guest halts on an invalid block, so no proof of a failed validation exists.
  - The chain is compiled into the ELF, and the ELF is identified by its program VK.
- The proof decodes completely, with no trailing bytes, and it is at most 4 MiB.
- It is a non-aggregated vadcop_final proof (`kind == Final`) of the configured hash family.
- The program VK committed in the STARK publics is one of the `--program-vk` values. The VK
  copy the proof stores alongside is ignored.
- Output words 0..7 (u32 little-endian) equal `new_payload_request_root`, and words 8..63 are zero.
- The STARK verifies under the pinned `--setup-vk` (`zisk-verifier` v1.3.2-alpha, the prover's
  release).

Both VKs are trusted configuration. A proof's own claimed VKs never count.

## Build

```bash
cd proof-engine && cargo build --release      # -> target/release/zisk-proof-engine
cargo test --release
```

## Run

```bash
zisk-proof-engine serve \
    --listen 127.0.0.1:9551 \
    --chain-id 11155111 \
    --program-vk 0x<32 bytes> \
    --setup-vk ~/.zisk/provingKey/zisk/vadcop_final/vadcop_final.verkey.json
```

- It serves `proof_type` 6, ZisK's EIP-8025 proof type (`api::ZISK_PROOF_TYPE`, the same
  constant the exex signs with). Any other type gets a 400.
- `--program-vk` identifies the guest ELF. The exex writes it to
  `<--zisk.out-dir>/program_vk.hex` at setup and also logs it. Repeat the flag to accept
  several builds, for example during an ELF upgrade.
- `--setup-vk` is the vadcop_final verkey of the proving key the workers use (`ziskup
  --provingkey`). It can be the JSON file or 32-byte hex.

Then start Lighthouse with `--proof-engine-endpoint http://127.0.0.1:9551`.

Two subcommands help with debugging:

- `zisk-proof-engine verify <proof.bin> --root 0x.. <same key flags>` verifies one file offline.
- `zisk-proof-engine inspect <proof.bin>` prints what a proof claims (its VKs, kind and committed
  root) without verifying anything. Use it to bootstrap the pinned VKs from a proof you
  produced yourself.

Each block directory the exex writes (`<number>-<hash>/proof.bin`) can be replayed by hand:

```bash
curl -s -X POST --data-binary @proof.bin -H 'content-type: application/octet-stream' \
  "http://127.0.0.1:9551/v1/execution_proof_verifications?new_payload_request_root=$ROOT&successful_validation=true&chain_id=11155111&schema_id=5377&proof_type=6"
```

# Tutorial: prove every block and submit the proofs (EIP-8025)

This tutorial sets up a **prover node**: a Sepolia reth node that proves every new block with
ZisK and publishes the proofs to the beacon network. It produces the proofs that a beacon
node without an execution client consumes. See
[tutorial-lighthouse-without-el.md](tutorial-lighthouse-without-el.md).

```
 beacon gossip ──▶ Lighthouse (unstable) ──execution_payload_gossip event──▶ reth-zisk ExEx
                       ▲      │                                              │ BAL input (ZEG0)
                       │      │ proof engine: verify                         ▼
                       │      ▼                                        ZisK coordinator
                       │  zisk-proof-engine                            (GPU workers)
                       │                                                     │ VadcopFinal STARK
  POST /eth/v1/beacon/execution_proofs ◀── BLS-signed SignedExecutionProofEnvelope (type 6)
                       │
                       └──▶ gossip topic `execution_proof` ──▶ other proof-verifying nodes
```

Each block goes through these steps:
1. `reth-zisk` (reth v2.7.0 plus the ExEx in [`reth-zisk-exex/`](../reth-zisk-exex/README.md))
   builds the guest input from the block access list, before reth has finished executing.
2. The ZisK coordinator proves it (about 5.5 s for a Sepolia block).
3. The ExEx signs the proof with a validator key, using `proof_type` 6, ZisK's EIP-8025 proof
   type.
4. It POSTs the proof to Lighthouse.
5. Lighthouse verifies it through `zisk-proof-engine` ([`proof-engine/`](../proof-engine/README.md))
   and gossips it.

From newPayload to submission takes about 6–7 s, inside the 12 s slot.

Values marked *(Sepolia, 2026-10)* are the ones in use when this was written.

## Requirements

- **A synced Sepolia reth datadir** with the `debug` namespace. `reth-zisk` replaces that reth
  and uses the same datadir and ports.
- **Lighthouse from `unstable`**, at commit `16ce0a072` (2026-10-08) or later. No release has
  `POST /eth/v1/beacon/execution_proofs` or the spec `SignedExecutionProofEnvelope` yet.
  v8.3.0-rc.0 answers `400 Unsupported endpoint version: v1`.
- **A ZisK coordinator with GPU workers**, ZisK **v1.3.2-alpha**. Its release must match
  `zisk-verifier` in the proof engine. You also need its proving key's
  `vadcop_final.verkey.json`, found at
  `<provingKey>/zisk/vadcop_final/vadcop_final.verkey.json` on the prover server.
- **An active validator's EIP-2335 keystore and its password**. Lighthouse only accepts proofs
  signed by an active validator.
- **Build tools**: rustc 1.95, `protoc`, cmake, and the xpack `riscv-none-elf-gcc` **14** for the
  guest ELF (see [CLAUDE.md](../CLAUDE.md)).

## 1. Build

```bash
cd ziskethone
# Host build once: it fetches evmone and intx for the ELF build.
cmake -S cpp-guest -B cpp-guest/build-sepolia -DEVM_BACKEND=evmone -DZEG_CHAIN=sepolia
cmake --build cpp-guest/build-sepolia -j

# The ZisK guest ELF for Sepolia (the chain is compiled in)
export PATH=$HOME/opt/xpack-riscv/xpack-riscv-none-elf-gcc-14.3.0-1/bin:$PATH
cmake -S cpp-guest/zisk -B cpp-guest/zisk/build-npr-sep-evmone -DEVM_BACKEND=evmone -DZEG_CHAIN=sepolia \
      -DCMAKE_TOOLCHAIN_FILE=$PWD/cpp-guest/zisk/toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build cpp-guest/zisk/build-npr-sep-evmone --target zisk_eth_guest.elf -j
ELF=$PWD/cpp-guest/zisk/build-npr-sep-evmone/zisk_eth_guest.elf

(cd reth-zisk-exex && cargo build --release)   # -> target/release/reth-zisk
(cd proof-engine   && cargo build --release)   # -> target/release/zisk-proof-engine

# Lighthouse unstable
git clone --branch unstable https://github.com/sigp/lighthouse.git ~/git/lighthouse-unstable
(cd ~/git/lighthouse-unstable && cargo build --release --locked --bin lighthouse)   # about 8 min
```

The guest must commit the `new_payload_request_root` exactly as Lighthouse computes it: the
consensus-specs gloas `NewPayloadRequest` as a ProgressiveContainer, with
`versioned_hashes: List[.., 4096]`. That is commit `e17ec3b` or later. An older ELF yields
proofs that Lighthouse rejects with `InvalidProof`.

## 2. Smoke-test the prover by hand

Before running the node, check that the coordinator can set up, execute and prove one block.
Use `zisk-prove-client` from the ZisK repo
(`cargo build --release -p zisk-prove-client`).

```bash
COORD=http://<COORDINATOR_HOST>:7000          # (Sepolia, 2026-10) 7000 is the client-facing port
PC=../zisk/target/release/zisk-prove-client

# A fresh witness: within 32 blocks of the head (see CLAUDE.md)
HEAD=$(curl -s -X POST http://127.0.0.1:8645 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | grep -o '0x[0-9a-f]*')
BLK=$((HEAD - 3))
./target/release/input-gen --rpc-url http://127.0.0.1:8645 --block $BLK --output /tmp/in.bin
./cpp-guest/build-sepolia/zisk_eth_guest /tmp/in.bin | tail -1      # the expected root

# ZisK stdin framing: u64 LE length, the data, zero padding to 8 bytes
python3 -c "import struct,sys;d=open('/tmp/in.bin','rb').read();o=struct.pack('<Q',len(d))+d;o+=b'\0'*(-len(o)%8);open('/tmp/in.zin','wb').write(o)"

$PC --coordinator $COORD setup   --elf $ELF                          # prints the hash_id (about 1 min)
$PC --coordinator $COORD execute -H <hash_id> -i /tmp/in.zin -o /tmp/out.bin
$PC --coordinator $COORD prove   -H <hash_id> -i /tmp/in.zin -o /tmp/proof.bin
```

- **Check `execute`**: it reports about 350–400 M steps in about 1 s. `/tmp/out.bin` holds the
  68 publics as u64: 4 VK words, which are zero in execute mode, then the root as 8 u32 words.
- **Check `prove`**: it finishes in about 5–6 s and writes a proof of about 935 KB.
- **Verify the proof offline**:
  ```bash
  E=proof-engine/target/release/zisk-proof-engine
  $E inspect /tmp/proof.bin        # the claimed program VK, setup VK and committed root (untrusted)
  $E verify /tmp/proof.bin --root <root> --chain-id 11155111 \
      --program-vk <program vk from inspect> --setup-vk vadcop_final.verkey.json   # -> VALID
  ```
  The setup VK that `inspect` prints must equal the prover's `vadcop_final.verkey.json`.

> **Always frame the input.** The exex frames it (`frame_input`), but `zisk-prove-client`
> sends the file as is. An unframed input made a worker drop its connection.

## 3. Lay out the host

The exex replaces the stock reth and shares its datadir, so stop the stock reth first. A
layout that works:

```
/usr/local/bin/{reth-zisk,zisk-proof-engine,lighthouse}   installed copies
~/data/zisk/etc/       reth-zisk.env, proof-engine.env                     (0750)
~/data/zisk/keys/      keystore.json, password.txt                         (0700, files 0600)
~/data/zisk/guest/     <date>-<sha>/zisk_eth_guest.elf, current -> the one in use
~/data/zisk/verkey/    vadcop_final.verkey.json
~/data/zisk/proofs/    --zisk.out-dir: program_vk.hex, <number>-<hash>/
```

Write the keystore password into `keys/password.txt` without leaving it in the shell history:
`read -rs P && printf '%s' "$P" > ~/data/zisk/keys/password.txt && unset P`.

## 4. First run: prove and sign, don't submit

Run `reth-zisk node` with **all of your reth flags** plus:

```bash
reth-zisk node --chain sepolia ... (the stock unit's flags, same --datadir) \
    --zisk.mode prove \
    --zisk.out-dir ~/data/zisk/proofs \
    --zisk.elf ~/data/zisk/guest/current/zisk_eth_guest.elf \
    --zisk.coordinator http://<COORDINATOR_HOST>:7000 \
    --zisk.beacon-url http://127.0.0.1:<LIGHTHOUSE_HTTP_PORT> \
    --zisk.keystore ~/data/zisk/keys/keystore.json \
    --zisk.keystore-password-file ~/data/zisk/keys/password.txt
```

Check the log:
```
reth_zisk: proof signer validator_index=… pubkey=… proof_type=6
reth_zisk::prover: registered guest program hash_id=…
reth_zisk::prover: guest program set up program_vk=… hash_mode=blake3
reth_zisk::prover: proof ready … bytes=935012 steps=… elapsed=5.5s
reth_zisk::pipeline: signed proof number=… slot=… beacon_root=…
```

- **Program VK**: it is also written to `proofs/program_vk.hex`. It identifies the ELF, and the
  proof engine pins it.
- **Catch-up**: on startup the exex skips old blocks (`stage="cancelled"`) and starts with the
  live head.
- **Slow first start**: after a restart, reth can spend about 5 minutes on "Three-way healing"
  and an unwind before the ExEx starts. Wait for it.

## 5. Proof engine and Lighthouse

```bash
zisk-proof-engine serve --listen 127.0.0.1:9551 --chain-id 11155111 \
    --program-vk $(cat ~/data/zisk/proofs/program_vk.hex) \
    --setup-vk ~/data/zisk/verkey/vadcop_final.verkey.json
curl -s 127.0.0.1:9551/v1/proof_types       # {"proof_types":[6]}
```

Add `--proof-engine-endpoint http://127.0.0.1:9551` to Lighthouse (unstable) and restart it.
Then restart `reth-zisk` with two more flags:

```bash
    --zisk.submit --zisk.lighthouse-early
```

`--zisk.lighthouse-early` is **required**. Once a proof engine is configured, Lighthouse no
longer sends `newPayload` to the EL: the proofs take its place. reth then only gets forkchoice
updates and fetches the blocks over p2p, so the exex's newPayload tap never fires. With the flag,
the exex follows Lighthouse's `execution_payload_gossip` events and fetches each payload
envelope from the beacon API.

## 6. Check the whole path

| Where | Expected |
|---|---|
| reth-zisk | `submitted proof number=… slot=…`, then `job finished … stage="submitted"` |
| zisk-proof-engine | `VALID root="…" bytes=935012 elapsed=…ms` for each block |
| Lighthouse (`beacon/logs/beacon.log`, debug) | `Publishing submitted execution proof … proof_type: 6` |

Lighthouse calls the proof engine with **its own** `new_payload_request_root`, so a VALID
verdict means the guest's root matches the beacon node's.

**Optimistic head**: this Lighthouse marks a payload valid only after proofs from
`REQUIRED_EXECUTION_PROOFS = 2` distinct proof systems. With ZisK as the only prover, its head
stays optimistic, and block and attestation production is disabled. Don't attach a validator
client to this beacon node. See tutorial 2 for running with one proof system.

If Lighthouse logs `Could not publish message error: NoPeersSubscribedToTopic, kind:
execution_proof`, none of its peers verifies proofs. Peer it with a proof-verifying node; see
tutorial 2, section "Peering".

## 7. Run it as services

Use systemd units that encode the steps above:
- **`reth-zisk-sepolia.service`**: the stock reth unit's flags plus the `--zisk.*` flags. Add
  `Conflicts=reth-sepolia.service` and `After=reth-sepolia.service`. The `After=` matters:
  `Conflicts=` alone doesn't order the swap, and the new node then fails with "storage directory
  is currently in use" until the old one has released the DB lock. Load the coordinator URL and
  the extra flags (`--zisk.submit --zisk.lighthouse-early`) from an `EnvironmentFile=`, and set
  `TimeoutStopSec=600`.
- **`zisk-proof-engine.service`**: the `serve` command, `Restart=always`.
- **A Lighthouse drop-in** (`lighthouse-sepolia.service.d/proof-engine.conf`). It clears
  `ExecStart=` and repeats the unit's flags plus `--proof-engine-endpoint`, with
  `Wants=`/`After=zisk-proof-engine.service`.
- **A daily prune timer**: the exex never deletes `proofs/<number>-<hash>/`, which takes about
  5 MB per block, or about 35 GB a day at 7,200 blocks a day:
  ```
  find ~/data/zisk/proofs -mindepth 1 -maxdepth 1 -type d -regex '.*/[0-9]+-[0-9a-f]+' -mtime +7 -exec rm -rf {} +
  ```

Switch the boot-time service with
`systemctl disable reth-sepolia && systemctl enable reth-zisk-sepolia`.

## Changing the guest ELF

A new ELF has a new program VK:
1. Pin the new ELF and restart reth-zisk. It registers the ELF and writes the new
   `program_vk.hex`.
2. While switching, give the proof engine both VKs, e.g. `--program-vk <new> --program-vk <old>`.
3. Drop the old one once no more of its proofs are in flight.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `POST execution_proofs: 400 … Unsupported endpoint version: v1` | Lighthouse is older than `16ce0a072`; build `unstable` |
| `400 … InvalidProof`, and the engine logs `proof commits new_payload_request_root 0x…, not 0x…` | the ELF predates `e17ec3b` (old NewPayloadRequest layout); rebuild and pin the ELF |
| No jobs after enabling the proof engine, though reth imports blocks | `--zisk.lighthouse-early` is missing (see section 5) |
| `job failed: … Cluster unavailable: workers are busy / setting up / insufficient ready capacity` | coordinator side. The exex skips those blocks without retrying and resumes on its own |
| `[Monitor] Phase Contributions timed out … (309s > 300s)` | the workers are too slow or stuck; check the cluster |
| `Worker … connection dropped` on a hand-made job | an unframed input (section 2) |
| reth logs `Storage lock already taken` at start | the old reth still holds the datadir; add `After=` (section 7) |
| ~5 min of `Three-way healing` / `Unwinding` after a restart | normal reth recovery; wait |
| `NoPeersSubscribedToTopic` | peer with a proof-verifying node (tutorial 2) |

## Rollback

1. Start the stock reth; `Conflicts=` stops reth-zisk. Re-enable it at boot.
2. Remove the Lighthouse drop-in and restart Lighthouse, so it calls `newPayload` again.
3. Lighthouse `unstable` moves the beacon DB to schema 32. To go back to a release, stop it and
   run `lighthouse db migrate --to 31 --network sepolia --datadir <datadir>` with the unstable
   binary first.

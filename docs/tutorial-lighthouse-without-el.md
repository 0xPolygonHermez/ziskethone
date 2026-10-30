# Tutorial: Lighthouse without an execution client (EIP-8025 proofs)

This tutorial runs a **Sepolia beacon node with no execution client**. Instead of re-executing
every payload, it accepts a payload as valid once a ZisK proof of it has been verified. It needs
three pieces:
- Lighthouse `unstable`;
- [`zisk-proof-engine`](../proof-engine/README.md), which verifies the proofs;
- a prover node that publishes the proofs, set up as in
  [tutorial-prove-and-submit.md](tutorial-prove-and-submit.md).

```
 prover node (reth-zisk + Lighthouse) ──gossip `execution_proof`──▶ Lighthouse (no EL)
                                                                      │  POST /v1/execution_proof_verifications
                                                                      ▼
                                                                 zisk-proof-engine ── VALID ──▶ payload VALID
```

How it works, in Lighthouse `unstable`:
- **No execution endpoint is needed.** With `--proof-engine-endpoint` set and no
  `--execution-endpoint`, Lighthouse runs without an execution layer, as long as the head is
  post-Gloas (PR #10262). It never sends `newPayload` or forkchoice updates, never builds a
  block locally, and turns off the `get_blobs` optimisation.
- **Payloads are imported optimistically.** A payload is promoted to VALID in fork choice once
  proofs from enough distinct proof systems have verified (PR #10198).
- **Proofs arrive over gossip**, on topic `/eth2/<fork digest>/execution_proof/ssz_snappy`.
  Lighthouse only subscribes to it when `--proof-engine-endpoint` is set. For each proof, it
  calls the proof engine with the `new_payload_request_root` it computed from its own copy of
  the payload, so the proof must commit exactly that root.

Limits: the node can't verify pre-Gloas payloads, and it can't propose a block it built
itself.

## Requirements

- **A small Linux VM.** 8 cores, 16 GB of RAM and about 300 GB of disk are plenty; the node
  uses only a fraction. Root isn't needed.
- **The binaries**: Lighthouse built from `unstable` (2026-10-08 or later) and
  `zisk-proof-engine`. You can copy them from a build host whose glibc is no newer than the
  target's.
- **From the prover**:
  - its program VK, the content of its `proofs/program_vk.hex`;
  - its `vadcop_final.verkey.json`;
  - its beacon node's ENR and peer id
    (`curl -s 127.0.0.1:<port>/eth/v1/node/identity`).
- **Network**: the prover's beacon node's p2p TCP port must be reachable from this VM.

Values marked *(Sepolia, 2026-10)* are the ones in use when this was written.

## 1. Install without root

```bash
mkdir -p ~/bin ~/data/lighthouse-sepolia ~/data/zisk/etc ~/data/zisk/verkey ~/.config/systemd/user
chmod 0750 ~/data/zisk/etc
scp <build-host>:git/lighthouse-unstable/target/release/lighthouse        ~/bin/
scp <build-host>:git/ziskethone/proof-engine/target/release/zisk-proof-engine ~/bin/
scp <prover>:data/zisk/verkey/vadcop_final.verkey.json ~/data/zisk/verkey/
loginctl enable-linger $USER      # user services keep running after logout and start at boot
```

## 2. The proof engine

`~/data/zisk/etc/proof-engine.env`:
```bash
PE_CHAIN_ID=11155111
PE_PROGRAM_VK=0x<the prover's program_vk.hex>
PE_SETUP_VK=/home/<you>/data/zisk/verkey/vadcop_final.verkey.json
PE_EXTRA_ARGS=
```

`~/.config/systemd/user/zisk-proof-engine.service`:
```ini
[Unit]
Description=ZisK EIP-8025 proof engine

[Service]
Restart=always
RestartSec=5
EnvironmentFile=%h/data/zisk/etc/proof-engine.env
ExecStart=%h/bin/zisk-proof-engine serve --listen 127.0.0.1:9551 \
    --chain-id ${PE_CHAIN_ID} --program-vk ${PE_PROGRAM_VK} --setup-vk ${PE_SETUP_VK} $PE_EXTRA_ARGS

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload && systemctl --user enable --now zisk-proof-engine
curl -s 127.0.0.1:9551/v1/proof_types          # {"proof_types":[6]}
```

The program VK pins the prover's ELF. When the prover switches ELF, add the new VK as a second
`--program-vk` in `PE_EXTRA_ARGS`, or the new proofs are INVALID (`program VK … is not pinned`).

## 3. Peering with the prover

Today, few beacon nodes carry the `execution_proof` topic:
- Lighthouse subscribes only when it has a proof engine;
- no other client implements the topic;
- gossipsub never relays a topic to nodes that haven't subscribed to it.

So on a public network the prover's proofs reach **only** the peers that subscribe. The prover
logs `Could not publish message error: NoPeersSubscribedToTopic, kind: execution_proof` until it
has one. Connect the two nodes directly:

- **This node dials the prover.** List the prover's ENR in `--boot-nodes`; Lighthouse dials every
  boot ENR over TCP at startup.
  - `--boot-nodes` **replaces** the network's built-in boot nodes, so repeat them too. For
    Sepolia they are in
    `common/eth2_network_config/built_in_network_configs/sepolia/bootstrap_nodes.yaml` in the
    Lighthouse repo (7 ENRs).
  - `--libp2p-addresses` is accepted but does nothing in this build.
- **The prover keeps this node.** A prover beacon node with a full peer table, 200+ peers, drops
  newcomers with `Too many peers`. Add this node's peer id to the prover's `--trusted-peers`
  (this node logs its id at startup, `Libp2p Starting peer_id: …`). Trusted peers are also
  re-dialed, but only once their address is known.
- **This node keeps the prover**: put the prover's peer id in this node's `--trusted-peers`.

`~/data/zisk/etc/lighthouse.env`:
```bash
PROVER_PEER_ID=16Uiu2…                 # the prover beacon node's peer_id
PROVER_ENR=enr:-QEAu…                  # its ENR
SEPOLIA_BOOT_ENRS=enr:-…,enr:-…        # the 7 built-in Sepolia ENRs, comma-separated
```

## 4. Lighthouse

`~/.config/systemd/user/lighthouse-sepolia.service`:
```ini
[Unit]
Description=Lighthouse Beacon Node Sepolia (no EL, EIP-8025 proofs)
Wants=network-online.target zisk-proof-engine.service
After=network-online.target zisk-proof-engine.service

[Service]
Restart=always
RestartSec=5
TimeoutStopSec=300
EnvironmentFile=%h/data/zisk/etc/lighthouse.env
ExecStart=%h/bin/lighthouse bn \
    --network sepolia \
    --datadir %h/data/lighthouse-sepolia \
    --checkpoint-sync-url https://checkpoint-sync.sepolia.ethpandaops.io \
    --http --http-address 127.0.0.1 --http-port 5052 \
    --proof-engine-endpoint http://127.0.0.1:9551 \
    --boot-nodes ${PROVER_ENR},${SEPOLIA_BOOT_ENRS} \
    --trusted-peers ${PROVER_PEER_ID}

[Install]
WantedBy=default.target
```

There is no `--execution-endpoint` and no JWT.

```bash
systemctl --user daemon-reload && systemctl --user enable --now lighthouse-sepolia
journalctl --user -fu lighthouse-sepolia
```

Check the startup line:
```
Running with no execution layer; EIP-8025 proofs decide payload validity
    info: "the node cannot verify pre-Gloas payloads or propose a locally built one"
```
After checkpoint sync, it catches up to the head within a few minutes.

Check that the prover is connected:
```bash
curl -s 127.0.0.1:5052/eth/v1/node/peers/<PROVER_PEER_ID> | grep -o '"state":"[a-z]*"'   # connected
```

## 5. One proof system or two

```rust
// beacon_node/beacon_chain/src/execution_proof_verification/mod.rs
/// Distinct proof systems that must prove a payload before fork choice calls it valid.
/// TODO(9658): make configurable.
pub const REQUIRED_EXECUTION_PROOFS: usize = 2;
```

ZisK (proof type 6) is the only proof system publishing on Sepolia today, so with the stock
value the head **stays optimistic**. The proofs still verify, but no payload is promoted:
```
WARN Head is optimistic  info: "chain not fully verified, block and attestation production disabled until execution engine syncs"
```

For a test deployment, set it to `1` and rebuild (about 5 min incremental):
```bash
cd ~/git/lighthouse-unstable && git checkout -b required-execution-proofs-1
sed -i 's/^pub const REQUIRED_EXECUTION_PROOFS: usize = 2;/pub const REQUIRED_EXECUTION_PROOFS: usize = 1;/' \
    beacon_node/beacon_chain/src/execution_proof_verification/mod.rs
cargo build --release --locked --bin lighthouse
```

This makes the node trust **a single proof system**: a soundness bug in ZisK, or in the guest,
would let an invalid payload through. That is fine for a testnet experiment; on a node that
matters, keep the multi-proof requirement.

## 6. Check that proofs arrive and are verified

| Where | Expected, for each block |
|---|---|
| zisk-proof-engine | `VALID root="…" bytes=935012 elapsed=…ms` |
| Lighthouse (`~/data/lighthouse-sepolia/beacon/logs/beacon.log`, debug) | `Verified execution proof from gossip … proof_type: 6, block_slot: …` |
| the same, with the patch | `Execution proofs complete, validating payload block_root: …` |
| `curl -s 127.0.0.1:5052/eth/v1/node/syncing` | with the patch: `"is_optimistic":false` |

After a restart, the first proofs often show `Could not verify execution proof … UnknownBlockRoot`
or `PayloadUnavailable`. The proof arrived before this node had its block, so Lighthouse dropped
it; those blocks stay optimistic. Once the node is at the head, the block arrives first: the proof
comes about 6 s into the slot, and verification starts.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Synced, but no `execution proof` lines at all | not connected to the prover: check the peering (section 3) |
| The prover logs `Peer Manager disconnecting peer … reason: Too many peers` for this node | add this node to the prover's `--trusted-peers` |
| `Failed to dial peer … No addresses for the peer to dial` | a trusted peer with no known address: put its ENR in `--boot-nodes` |
| `Could not verify execution proof … UnknownBlockRoot / PayloadUnavailable` | the node is behind the head; it clears once synced |
| The proof engine logs `INVALID … program VK … is not pinned` | the prover changed ELF: add its new VK |
| The proof engine logs `INVALID … proof commits new_payload_request_root …` | the prover runs an ELF older than `e17ec3b` |
| The head goes back to optimistic | the prover stopped producing proofs (e.g. its ZisK cluster is down); it recovers when proofs resume |

## Rollback

- **Plain Lighthouse with an EL**: drop `--proof-engine-endpoint` and add `--execution-endpoint`
  and `--execution-jwt` for an execution client.
- **A Lighthouse release**: the unstable build moved the beacon DB to schema 32, so stop the
  node and run `lighthouse db migrate --to 31 --network sepolia --datadir ~/data/lighthouse-sepolia`
  with the unstable binary before swapping binaries.

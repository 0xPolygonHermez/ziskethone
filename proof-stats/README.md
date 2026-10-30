# proof-stats — proof-lifecycle timing accumulator

Accumulates a durable, historical record of each Sepolia block's proof lifecycle on the
live prover — from the block timestamp until the proof-engine has verified the proof —
broken into stages. It does this **by scraping the existing journald logs** of the two
services; it changes nothing in the prover, needs no rebuild, and adds no downtime.

## Pipeline it measures

```
block ts ──► exex sees block ──► build input ──► prove (coordinator) ──► sign ──► POST to beacon
                                                                                     │
                       proof-engine verifies ◄── beacon forwards ◄────────────────────┘
```

- **exex** = `reth-zisk-sepolia.service` (logs target `reth_zisk::pipeline`/`::prover`)
- **proof engine** = `zisk-proof-engine.service` (verifies, logs `VALID`/`INVALID`)

## Metrics (per block; see `schema.sql` for all columns)

| column | meaning |
|---|---|
| `recv_lag_ms`    | block timestamp → exex first sees the block |
| `input_build_ms` | input building (`witness_ms` is the witness/BAL sub-part) |
| `prove_ms`       | coordinator proving time |
| `sign_ms`        | signing the proof |
| `propagation_ms` | exex handoff (`signed proof`) → proof-engine starts verifying (incl. beacon forward) |
| `validation_ms`  | proof-engine verification time |
| `roundtrip_ms`   | whole beacon+verify round trip (`signed`→`submitted`) |
| `end_to_end_ms`  | **block timestamp → proof verified by the proof-engine** |

Raw absolute anchors (UTC unix ms) and the raw exex `timings` JSON are stored too, so
any metric can be recomputed from history later.

## How the two sides are joined

`new_payload_request_root` is **not** logged by the exex (and `public_input.json` is not
written in prove mode), so the exex block and the proof-engine verification are paired by
**time**: each `VALID`/`INVALID` lands within ~1–2 ms of the exex `submitted proof` for the
same block, and blocks are ~12 s apart, so the nearest-timestamp match (±2 s) is 1:1. The
proof-engine line then supplies `root` to that block. Primary key is the block `hash`.

Note: journald exports `MESSAGE` as a byte array when it contains ANSI colour codes; the
collector decodes `list[int]→bytes→utf8` and strips the escapes. Each event is timestamped
from its own in-message ISO timestamp, so both services share one UTC-ms timeline.

## Run

Durable DB lives at `/home/jbaylina/data/zisk/stats/stats.db` (outside git).

```bash
# one-shot backfill from the retained journal (seed history)
python3 collector.py --db /home/jbaylina/data/zisk/stats/stats.db --backfill --since "today"

# continuous follower (installed as a service; resumes via a journald cursor stored in the DB)
sudo cp zisk-proof-stats.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zisk-proof-stats.service
```

## Report

```bash
python3 report.py --db /home/jbaylina/data/zisk/stats/stats.db            # mean/p50/p90/p99/max per stage, in seconds
python3 report.py --db .../stats.db --last 200                            # only the latest 200 blocks
python3 report.py --db .../stats.db --since "2026-10-17"                   # only blocks from a date
python3 report.py --db .../stats.db --csv > blocks.csv                     # raw per-block rows
```

`sqlite3` CLI is not installed on the host; query with Python's `sqlite3` module or `report.py`.

## Notes / limits

- The collector is read-only w.r.t. the system (journald + its own DB dir); it never touches
  the prover, beacon node, or proof dirs.
- The exex's per-block `zisk-proofs` dirs are pruned after 7 days; this DB is the permanent
  record, so keep the collector running to capture blocks before they age out of the journal.
- Cancelled/reorged blocks are stored exex-side with `validity=NULL` and no end-to-end time.
- Optional future enhancement (needs a redeploy, ~7 min resync): add `submitted`/`verified`
  timeline marks + a `job_id↔number` log line to the exex for exact propagation and step
  attribution without the time-proximity join.

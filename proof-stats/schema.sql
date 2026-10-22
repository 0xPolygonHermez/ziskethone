-- Per-block proof-lifecycle timing record. One row per block (PK = block hash).
-- All *_ms absolute anchors are UTC unix milliseconds; all derived *_ms are durations.
CREATE TABLE IF NOT EXISTS blocks (
    hash            TEXT PRIMARY KEY,   -- block hash (0x…), stable/unique
    number          INTEGER,
    slot            INTEGER,
    root            TEXT,               -- new_payload_request_root (from proof-engine), NULL if never verified
    beacon_root     TEXT,
    source          TEXT,               -- lh_envelope / lh_gossip / tap_payload (how the exex first saw it)
    result_stage    TEXT,               -- submitted / cancelled
    validity        TEXT,               -- VALID / INVALID / NULL (not verified: cancelled/reorged)
    invalid_reason  TEXT,

    -- absolute anchors (UTC unix ms)
    block_ts_ms     INTEGER,            -- block header timestamp = t0_unix_ms - t0_after_slot_start_ms
    t0_ms           INTEGER,            -- exex t0 (newpayload_received, else earliest mark)
    first_seen_ms   INTEGER,            -- earliest arrival mark (lh_gossip/lh_envelope/tap_payload/newpayload)
    input_start_ms  INTEGER,
    witness_done_ms INTEGER,
    input_done_ms   INTEGER,
    prove_start_ms  INTEGER,
    prove_done_ms   INTEGER,
    executed_ms     INTEGER,            -- reth finished executing the block
    signed_ms       INTEGER,            -- exex 'signed proof' (handoff to beacon)
    submitted_ms    INTEGER,            -- exex 'submitted proof' (beacon round-trip returned)
    verify_start_ms INTEGER,            -- PE verify begin = verify_finish_ms - validation_ms
    verify_finish_ms INTEGER,           -- PE 'VALID'/'INVALID' log time

    -- derived durations (ms) — the six requested metrics + sub-parts
    recv_lag_ms     REAL,               -- (1) first_seen - block_ts
    input_build_ms  REAL,               -- (2) input_done - input_start
    witness_ms      REAL,               --      witness_done - input_start (sub-part of input build)
    prove_ms        REAL,               -- (3) prove_done - prove_start
    sign_ms         REAL,               --      signed - prove_done (signing)
    propagation_ms  REAL,               -- (4) verify_start - signed
    validation_ms   REAL,               -- (5) PE elapsed
    roundtrip_ms    REAL,               --      submitted - signed (whole beacon+PE round trip)
    end_to_end_ms   REAL,               -- (6) verify_finish - block_ts

    -- extras
    gas_used        INTEGER,            -- block gasUsed (from the Sepolia RPC), for size/time correlation
    steps           INTEGER,            -- ZisK steps (from prover 'proof ready')
    proof_bytes     INTEGER,
    prove_elapsed_ms REAL,              -- prover-reported coordinator round-trip
    input_bytes     INTEGER,            -- framed input size sent to the coordinator (bytes)
    input_send_ms   REAL,               -- exex→coordinator input upload / network time
    queue_wait_ms   REAL,               -- busy-retry time before a worker accepted the job
    job_id          TEXT,
    timings_json    TEXT,               -- raw exex timings object, for future recomputation
    ingested_at_ms  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_blocks_number   ON blocks(number);
CREATE INDEX IF NOT EXISTS idx_blocks_block_ts ON blocks(block_ts_ms);
CREATE INDEX IF NOT EXISTS idx_blocks_root     ON blocks(root);

-- Collector bookkeeping (journald cursor for resume-without-gaps).
CREATE TABLE IF NOT EXISTS collector_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);

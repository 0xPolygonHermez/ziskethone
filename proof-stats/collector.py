#!/usr/bin/env python3
"""Accumulate per-block proof-lifecycle timing stats for the live ZisK Sepolia prover.

Scrapes the journald logs of the exex (reth-zisk-sepolia.service) and the proof
engine (zisk-proof-engine.service) — no change to either service — and writes one
durable row per block to a SQLite DB. See README.md for the metric definitions.

The exex log supplies, per block `number`: the timing vector (t0 + ms_from_t0
marks), slot/beacon_root (signed proof), submit time (submitted proof), hash/stage
(job finished), and steps/bytes (prover 'proof ready'). The proof engine supplies,
per `new_payload_request_root`: validation elapsed + verify-finish time. The two
sides are joined by time-proximity: each PE verify lands <2 ms from the exex
'submitted proof' of the same block, and blocks are ~12 s apart.

Usage:
  collector.py --db DB --cursor-file CUR            # follow live (systemd service)
  collector.py --db DB --backfill --since "today"   # one-shot seed from retained journal
"""
import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request
from collections import deque, OrderedDict
from datetime import datetime, timezone

EXEX_UNIT = "reth-zisk-sepolia.service"
PE_UNIT = "zisk-proof-engine.service"

# Local Sepolia RPC used only to enrich each row with the block's gasUsed.
# Best-effort: if it is unreachable, gas_used is left NULL and can be backfilled later.
DEFAULT_RPC = os.environ.get("ZISK_STATS_RPC", "http://127.0.0.1:8645")

ANSI = re.compile(r"\x1b\[[0-9;]*m")
TS_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)Z\s+")

# exex (target reth_zisk::pipeline / ::prover)
RE_JOB_TIMINGS = re.compile(r"job timings number=(\d+) timings=(\{.*\})\s*$")
RE_SIGNED = re.compile(r"signed proof number=(\d+) slot=(\d+) beacon_root=([0-9a-fx]+)")
RE_SUBMITTED = re.compile(r"submitted proof number=(\d+) slot=(\d+)")
RE_JOB_FINISHED = re.compile(r'job finished number=(\d+) hash=(0x[0-9a-f]+) stage="([^"]*)"')
RE_PROOF_READY = re.compile(
    r"proof ready job_id=(\S+) bytes=(\d+) steps=(\d+) elapsed=([0-9.]+)(ms|s|µs|us|ns)")
# proof engine
RE_PE = re.compile(r'(VALID|INVALID) root="([0-9a-f]+)" bytes=(\d+)')
RE_ELAPSED = re.compile(r"elapsed=([0-9.]+)(ms|s|µs|us|ns)")
RE_REASON = re.compile(r'reason="?([^"]*?)"?\s*(?:elapsed=|$)')

MATCH_WINDOW_MS = 2000.0   # PE verify ↔ exex submitted proof


def decode_message(m):
    """journald MESSAGE is a str, or a list[int] of raw bytes when it had ANSI codes."""
    if isinstance(m, list):
        try:
            m = bytes(b & 0xFF for b in m).decode("utf-8", "replace")
        except Exception:
            return ""
    if not isinstance(m, str):
        return ""
    return ANSI.sub("", m)


def iso_to_ms(s):
    # s like 2026-10-17T09:28:44.984631 (no trailing Z)
    try:
        dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
        return dt.timestamp() * 1000.0
    except ValueError:
        return None


def elapsed_to_ms(val, unit):
    v = float(val)
    return {"ms": v, "s": v * 1000.0, "µs": v / 1000.0, "us": v / 1000.0,
            "ns": v / 1e6}.get(unit, v)


def fetch_gas_used(number, rpc=DEFAULT_RPC, timeout=3.0):
    """Best-effort gasUsed for a block number via JSON-RPC. None on any failure."""
    if not rpc:
        return None
    try:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
                              "params": [hex(number), False]}).encode()
        req = urllib.request.Request(rpc, data=payload,
                                     headers={"Content-Type": "application/json"})
        res = json.load(urllib.request.urlopen(req, timeout=timeout)).get("result")
        return int(res["gasUsed"], 16) if res and res.get("gasUsed") else None
    except Exception:
        return None


class Collector:
    def __init__(self, db_path, rpc=DEFAULT_RPC):
        self.rpc = rpc
        first = not os.path.exists(db_path) or os.path.getsize(db_path) == 0
        self.db = sqlite3.connect(db_path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        schema = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
        with open(schema) as f:
            self.db.executescript(f.read())
        # idempotent migration: add columns introduced after the DB was first created
        have = {r[1] for r in self.db.execute("PRAGMA table_info(blocks)")}
        for col, decl in (("gas_used", "INTEGER"),):
            if col not in have:
                self.db.execute("ALTER TABLE blocks ADD COLUMN %s %s" % (col, decl))
        self.db.commit()
        # in-flight exex blocks keyed by number (bounded LRU)
        self.blocks = OrderedDict()
        # unmatched PE verify events: (verify_finish_ms, root, validity, bytes, validation_ms, reason)
        self.pe_pending = deque()
        self.last_proof_ready = None  # (job_id, bytes, steps, prove_elapsed_ms)
        self.inserted = 0

    # ---- block record helpers ----
    def block(self, number):
        b = self.blocks.get(number)
        if b is None:
            b = {"number": number}
            self.blocks[number] = b
        self.blocks.move_to_end(number)
        while len(self.blocks) > 200:
            self.blocks.popitem(last=False)
        return b

    def prune_pe(self, now_ms):
        while self.pe_pending and now_ms - self.pe_pending[0][0] > 60000:
            self.pe_pending.popleft()

    # ---- line handlers ----
    def on_exex(self, msg, line_ms):
        m = RE_PROOF_READY.search(msg)
        if m:
            self.last_proof_ready = (m.group(1), int(m.group(2)), int(m.group(3)),
                                     elapsed_to_ms(m.group(4), m.group(5)))
            return
        m = RE_SIGNED.search(msg)
        if m:
            b = self.block(int(m.group(1)))
            b["slot"] = int(m.group(2))
            br = m.group(3)
            b["beacon_root"] = br if br.startswith("0x") else "0x" + br
            b["signed_ms"] = line_ms
            if self.last_proof_ready and "job_id" not in b:
                b["job_id"], b["proof_bytes"], b["steps"], b["prove_elapsed_ms"] = self.last_proof_ready
                self.last_proof_ready = None
            return
        m = RE_SUBMITTED.search(msg)
        if m:
            b = self.block(int(m.group(1)))
            b.setdefault("slot", int(m.group(2)))
            b["submitted_ms"] = line_ms
            self.match_pe(b)
            return
        m = RE_JOB_FINISHED.search(msg)
        if m:
            b = self.block(int(m.group(1)))
            b["hash"] = m.group(2)
            b["result_stage"] = m.group(3)
            return
        m = RE_JOB_TIMINGS.search(msg)
        if m:
            b = self.block(int(m.group(1)))
            try:
                t = json.loads(m.group(2))
            except json.JSONDecodeError:
                return
            b["timings"] = t
            self.finalize(b)  # terminal event for the block
            return

    def on_pe(self, msg, line_ms):
        m = RE_PE.search(msg)
        if not m:
            return
        el = RE_ELAPSED.search(msg)
        validation_ms = elapsed_to_ms(el.group(1), el.group(2)) if el else None
        reason = None
        if m.group(1) == "INVALID":
            rm = RE_REASON.search(msg)
            reason = rm.group(1) if rm else None
        self.pe_pending.append((line_ms, m.group(2), m.group(1), int(m.group(3)),
                                validation_ms, reason))
        self.prune_pe(line_ms)

    def match_pe(self, b):
        """Attach the PE verify event nearest to this block's submit time."""
        ts = b.get("submitted_ms")
        if ts is None or not self.pe_pending:
            return
        best_i, best_d = None, MATCH_WINDOW_MS
        for i, ev in enumerate(self.pe_pending):
            d = abs(ev[0] - ts)
            if d < best_d:
                best_i, best_d = i, d
        if best_i is None:
            return
        fin, root, validity, pbytes, validation_ms, reason = self.pe_pending[best_i]
        del self.pe_pending[best_i]
        b["root"] = root
        b["validity"] = validity
        b["invalid_reason"] = reason
        b["verify_finish_ms"] = fin
        b["validation_ms"] = validation_ms
        if validation_ms is not None:
            b["verify_start_ms"] = fin - validation_ms
        b.setdefault("proof_bytes", pbytes)

    # ---- compute derived + upsert ----
    def finalize(self, b):
        t = b.get("timings") or {}
        marks = t.get("ms_from_t0") or {}
        t0 = t.get("t0_unix_ms")
        off = t.get("t0_after_slot_start_ms")
        if t0 is not None:
            b["t0_ms"] = t0
            if off is not None:
                b["block_ts_ms"] = t0 - off
            for k, col in (("input_start", "input_start_ms"), ("witness_done", "witness_done_ms"),
                           ("input_done", "input_done_ms"), ("prove_start", "prove_start_ms"),
                           ("prove_done", "prove_done_ms"), ("executed", "executed_ms")):
                if k in marks:
                    b[col] = t0 + marks[k]
            arrival = [marks[k] for k in ("lh_gossip", "lh_envelope", "tap_payload",
                                          "newpayload_received") if k in marks]
            first_off = min([0.0] + arrival)
            b["first_seen_ms"] = t0 + first_off
            if "source" not in b:
                # earliest arrival label = how it was first seen
                lbl = min(((marks[k], k) for k in ("lh_gossip", "lh_envelope", "tap_payload",
                           "newpayload_received") if k in marks), default=(None, None))[1]
                b["source"] = lbl
            b["timings_json"] = json.dumps(t, separators=(",", ":"))

        def d(a, c):
            return (b[a] - b[c]) if (b.get(a) is not None and b.get(c) is not None) else None

        b["recv_lag_ms"] = d("first_seen_ms", "block_ts_ms")
        b["input_build_ms"] = d("input_done_ms", "input_start_ms")
        b["witness_ms"] = d("witness_done_ms", "input_start_ms")
        b["prove_ms"] = d("prove_done_ms", "prove_start_ms")
        b["sign_ms"] = d("signed_ms", "prove_done_ms")
        b["propagation_ms"] = d("verify_start_ms", "signed_ms")
        b["roundtrip_ms"] = d("submitted_ms", "signed_ms")
        b["end_to_end_ms"] = d("verify_finish_ms", "block_ts_ms")
        if b.get("gas_used") is None:
            b["gas_used"] = fetch_gas_used(b["number"], self.rpc)
        self.upsert(b)
        self.blocks.pop(b["number"], None)

    COLS = ["hash", "number", "slot", "root", "beacon_root", "source", "result_stage",
            "validity", "invalid_reason", "block_ts_ms", "t0_ms", "first_seen_ms",
            "input_start_ms", "witness_done_ms", "input_done_ms", "prove_start_ms",
            "prove_done_ms", "executed_ms", "signed_ms", "submitted_ms", "verify_start_ms",
            "verify_finish_ms", "recv_lag_ms", "input_build_ms", "witness_ms", "prove_ms",
            "sign_ms", "propagation_ms", "validation_ms", "roundtrip_ms", "end_to_end_ms",
            "gas_used", "steps", "proof_bytes", "prove_elapsed_ms", "job_id", "timings_json",
            "ingested_at_ms"]

    def upsert(self, b):
        key = b.get("hash") or ("pending-%d" % b["number"])  # hash missing only if job-finished lost
        b.setdefault("hash", key)
        b["ingested_at_ms"] = int(time.time() * 1000)
        cols = self.COLS
        vals = [b.get(c) for c in cols]
        updates = ",".join("%s=excluded.%s" % (c, c) for c in cols if c != "hash")
        sql = ("INSERT INTO blocks (%s) VALUES (%s) ON CONFLICT(hash) DO UPDATE SET %s"
               % (",".join(cols), ",".join("?" * len(cols)), updates))
        self.db.execute(sql, vals)
        self.inserted += 1

    def save_cursor(self, cursor):
        self.db.execute("INSERT INTO collector_state(key,value) VALUES('cursor',?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (cursor,))

    def load_cursor(self):
        r = self.db.execute("SELECT value FROM collector_state WHERE key='cursor'").fetchone()
        return r[0] if r else None

    # ---- main ingest of one journald json line ----
    def handle(self, o):
        msg = decode_message(o.get("MESSAGE"))
        if not msg:
            return
        pm = TS_PREFIX.match(msg)
        line_ms = iso_to_ms(pm.group(1)) if pm else None
        if line_ms is None:
            rt = o.get("__REALTIME_TIMESTAMP")  # microseconds
            line_ms = float(rt) / 1000.0 if rt else None
        if line_ms is None:
            return
        unit = o.get("_SYSTEMD_UNIT", "")
        if unit == PE_UNIT or "zisk_proof_engine" in msg:
            self.on_pe(msg, line_ms)
        elif unit == EXEX_UNIT or "reth_zisk" in msg:
            self.on_exex(msg, line_ms)


def run(args):
    c = Collector(args.db, rpc=args.rpc_url)
    cmd = ["journalctl", "-o", "json", "-u", EXEX_UNIT, "-u", PE_UNIT]
    if args.backfill:
        cmd += ["--no-pager"]
        if args.since:
            cmd += ["--since", args.since]
    else:
        cmd += ["--follow", "-n", "0"]
        cur = c.load_cursor()
        if cur:
            cmd += ["--after-cursor", cur]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
    last_commit = time.time()
    n = 0
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                c.handle(o)
            except Exception as e:  # never die on one bad line
                print("parse error: %s" % e, file=sys.stderr)
            cur = o.get("__CURSOR")
            n += 1
            now = time.time()
            if not args.backfill and cur and (now - last_commit > 2.0):
                c.save_cursor(cur)
                c.db.commit()
                last_commit = now
            elif args.backfill and n % 5000 == 0:
                c.db.commit()
    except KeyboardInterrupt:
        pass
    finally:
        if not args.backfill:
            cur = None
            # best-effort: cursor already saved periodically
        c.db.commit()
        proc.terminate()
    print("processed %d journal lines, %d row upserts" % (n, c.inserted), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True)
    ap.add_argument("--cursor-file", help="(unused; cursor is stored in the DB) kept for unit compat")
    ap.add_argument("--backfill", action="store_true", help="one-shot: read retained journal, no follow")
    ap.add_argument("--since", help="backfill start, e.g. 'today' or '2026-10-17 06:00:00'")
    ap.add_argument("--rpc-url", default=DEFAULT_RPC,
                    help="Sepolia RPC for gasUsed enrichment (empty to disable)")
    run(ap.parse_args())


if __name__ == "__main__":
    main()

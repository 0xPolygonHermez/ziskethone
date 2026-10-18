#!/usr/bin/env python3
"""Summarise accumulated proof-lifecycle timing stats.

  report.py --db DB [--since '2026-10-17'] [--last N] [--csv]

Prints count + mean/p50/p90/p99/max (in seconds) for each lifecycle stage and the
end-to-end time (block timestamp → proof verified by the proof engine). --csv dumps
the raw per-block rows instead.
"""
import argparse
import csv
import sqlite3
import sys

# (column, label) in lifecycle order
METRICS = [
    ("recv_lag_ms",    "receive-lag       (block ts → exex sees block)"),
    ("input_build_ms", "input building    (input_start → input_done)"),
    ("witness_ms",     "  └ witness/BAL   (input_start → witness_done)"),
    ("prove_ms",       "proving           (prove_start → prove_done)"),
    ("sign_ms",        "signing           (prove_done → signed)"),
    ("propagation_ms", "propagation       (signed → PE verify start)"),
    ("validation_ms",  "validation        (PE verify elapsed)"),
    ("roundtrip_ms",   "  └ submit round  (signed → submitted)"),
    ("end_to_end_ms",  "END-TO-END        (block ts → PE verified)"),
]


def pct(sorted_vals, q):
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = q * (len(sorted_vals) - 1)
    lo = int(pos)
    frac = pos - lo
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac


def where(args):
    cl, params = [], []
    if args.since:
        cl.append("block_ts_ms >= (strftime('%s', ?) * 1000)")
        params.append(args.since)
    sql = (" WHERE " + " AND ".join(cl)) if cl else ""
    return sql, params


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True)
    ap.add_argument("--since", help="only blocks with timestamp >= this (e.g. 'today', '2026-10-17')")
    ap.add_argument("--last", type=int, help="only the latest N blocks by number")
    ap.add_argument("--csv", action="store_true", help="dump raw rows as CSV to stdout")
    args = ap.parse_args()

    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row
    wsql, params = where(args)

    if args.last:
        base = "SELECT * FROM (SELECT * FROM blocks%s ORDER BY number DESC LIMIT ?)" % wsql
        params = params + [args.last]
    else:
        base = "SELECT * FROM blocks" + wsql

    rows = db.execute(base + " ORDER BY number", params).fetchall()

    if args.csv:
        w = csv.writer(sys.stdout)
        if rows:
            w.writerow(rows[0].keys())
            for r in rows:
                w.writerow([r[k] for k in r.keys()])
        return

    total = len(rows)
    verified = sum(1 for r in rows if r["validity"] == "VALID")
    invalid = sum(1 for r in rows if r["validity"] == "INVALID")
    unver = total - verified - invalid
    print("blocks: %d total  |  %d VALID  %d INVALID  %d not-verified (cancelled/reorged)"
          % (total, verified, invalid, unver))
    if rows:
        nums = [r["number"] for r in rows if r["number"] is not None]
        if nums:
            print("range : #%d … #%d" % (min(nums), max(nums)))
    print()
    hdr = "%-46s %6s %8s %8s %8s %8s %8s" % ("stage", "n", "mean", "p50", "p90", "p99", "max")
    print(hdr)
    print("-" * len(hdr))
    for col, label in METRICS:
        vals = sorted(r[col] / 1000.0 for r in rows if r[col] is not None)
        if not vals:
            print("%-46s %6d %8s" % (label, 0, "-"))
            continue
        mean = sum(vals) / len(vals)
        print("%-46s %6d %8.3f %8.3f %8.3f %8.3f %8.3f"
              % (label, len(vals), mean, pct(vals, .5), pct(vals, .9),
                 pct(vals, .99), vals[-1]))
    print("\n(all times in seconds)")


if __name__ == "__main__":
    main()

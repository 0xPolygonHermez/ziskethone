#!/usr/bin/env python3
"""The heap gate: run a fixed set of killer blocks on a heap-stats ELF and fail
if any block's heap or arena use regresses past its baseline, the bound, or a
hard share of the ELF's heap (see HEAP_BUDGET.md and the Makefile `heap-gate`).

The guest's memory safety rests on the fixes in GLAMSTERDAM.md; this gate keeps a
later change from silently reopening one. It reuses scripts/killer_sweep.sh with
a pinned ZEG_HASH_SEED (inputs are byte-identical run to run) and ONLY_BLOCKS
(only the gate's blocks are bridged, generated and emulated), then parses the
HEAP lines the heap-stats ELF prints.

Per block (keyed by name, from the `HEAP` phase lines + the `HEAP block` line):
    in_used   = used at state_root           # input parse + old-root walk
    fixed     = used(state_db) - used(state_root)   # the analysis cache
    exec_used = used(end) - used(state_db)   # execution + new root + output
    tx_peak   = arena peak over the run
    gas_used, regular, state, txs, input, fork

Data files (scripts/heap_gate/):
    blocks-<GAS>.txt            lines: <fixture_relpath>\\t<name>\\t<reason>
    baseline-<GAS>-<backend>.tsv   per-block metrics, with a header comment

Modes:
    (default)      run the gate blocks and compare to the baseline  -> exit 0/1/2
    --update       rewrite the baseline from this run (if every other check passes)
    --skip-run     parse an existing OUT instead of running (for --select/--update)
    --all          parse OUT as a full run (every block), not just the gate list
    --select N     from a full run (--skip-run --all), print a blocks-<GAS>.txt
                   of the heaviest N-ish blocks per metric plus one per family
Exit: 0 pass, 1 gate failure, 2 setup error.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import heap_bound  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_DIR = REPO_ROOT / "scripts" / "heap_gate"

# Pinned per-run hash seed (16 bytes hex): makes the gate's inputs byte-identical
# across runs. Memory is seed-independent anyway (the maps grow by count), but a
# fixed seed lets a rerun reuse inputs and keeps step counts comparable.
SEED = "5a45474841504741544553454544aa55"

FORK_NAME = {1: "Berlin", 2: "London", 3: "Paris", 4: "Shanghai", 5: "Cancun",
             6: "Prague", 7: "Osaka", 8: "Amsterdam"}

# Default tolerances; overridable by env.
TOL_PCT = float(os.environ.get("HEAP_TOL_PCT", "2.0"))
TOL_ABS = int(os.environ.get("HEAP_TOL_MB", "0") or 0) * 1_000_000 or 256 * 1024
FIXED_TOL = 64 * 1024
MAX_SHARE = float(os.environ.get("HEAP_MAX_SHARE", "0.60"))

BASELINE_COLS = ["name", "in_used", "fixed", "exec_used", "tx_peak",
                 "gas_used", "txs", "input", "fork"]


def die(msg, code=2):
    print(f"heap_gate: {msg}", file=sys.stderr)
    sys.exit(code)


def load_block_list(gas):
    path = GATE_DIR / f"blocks-{gas}.txt"
    if not path.exists():
        die(f"no block list {path} (run --select from a full run first)")
    fixtures, names, reasons = [], [], {}
    for line in path.read_text().splitlines():
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue
        f = line.split("\t")
        fixtures.append(f[0])
        names.append(f[1])
        reasons[f[1]] = f[2] if len(f) > 2 else ""
    return path, fixtures, names, reasons


def parse_emu_log(path):
    """Metrics from one block's ziskemu log, or None if it never reached `end`
    (halt / OOM). `oom` is set if an out-of-memory line is present."""
    phase = {}
    blk = {}
    oom = None
    for line in Path(path).read_text(errors="replace").splitlines():
        if "out of memory" in line:
            oom = line.strip()
        if not line.startswith("HEAP "):
            continue
        if line.startswith("HEAP block "):
            for k, v in re.findall(r"(\w+)=(\d+)", line):
                blk[k] = int(v)
            continue
        m = re.match(r"HEAP (\w+) used=(\d+) tx_peak=(\d+) free=(\d+)", line)
        if m:
            phase[m.group(1)] = (int(m.group(2)), int(m.group(3)), int(m.group(4)))
    if oom or "end" not in phase or "state_root" not in phase or "state_db" not in phase:
        return None, oom, phase
    in_used = phase["state_root"][0]
    fixed = phase["state_db"][0] - phase["state_root"][0]
    exec_used = phase["end"][0] - phase["state_db"][0]
    tx_peak = phase["end"][1]
    return {
        "in_used": in_used, "fixed": fixed, "exec_used": exec_used, "tx_peak": tx_peak,
        "used_end": phase["end"][0],
        "gas_used": blk.get("gas_used", 0), "regular": blk.get("regular", 0),
        "state": blk.get("state", 0), "txs": blk.get("txs", 0),
        "input": blk.get("input", 0), "fork": FORK_NAME.get(blk.get("fork", 8), "Amsterdam"),
    }, oom, phase


def collect(out_dir):
    """name -> (metrics|None, verdict, oom) for every block in OUT/blocks.run."""
    run = Path(out_dir) / "blocks.run"
    if not run.exists():
        die(f"no {run}; run the sweep first (or drop --skip-run)")
    verdicts = {}
    for line in (Path(out_dir) / "results.log").read_text().splitlines():
        f = line.split()
        if len(f) >= 6:
            verdicts[f[-1]] = f[0]
    out = {}
    for line in run.read_text().splitlines():
        f = line.split()
        if len(f) < 8 or f[0] != "OK":
            continue
        base, name = f[5], f[7]
        metrics, oom, _ = parse_emu_log(f"{base}.emu.log") if Path(f"{base}.emu.log").exists() else (None, None, {})
        out[name] = (metrics, verdicts.get(name, "?"), oom)
    return out


def run_sweep(args, names, fixtures):
    only = Path(args.out) / "only_blocks.txt"
    Path(args.out).mkdir(parents=True, exist_ok=True)
    only.write_text("\n".join(names) + "\n")
    if not args.resume:
        for sub in ("p1", "work"):
            d = Path(args.out) / sub
            if d.exists():
                subprocess.run(["rm", "-rf", str(d)], check=True)
    fixture_paths = [str(Path(args.fixtures) / f) for f in sorted(set(fixtures))]
    env = dict(os.environ, ZEG_HASH_SEED=SEED, ONLY_BLOCKS=str(only),
               P1_JOBS=os.environ.get("P1_JOBS", "2"))
    cmd = [str(REPO_ROOT / "scripts" / "killer_sweep.sh"),
           "-g", args.host, "-e", args.elf, "-z", args.ziskemu,
           "-o", args.out, "-j", str(args.jobs), *fixture_paths]
    print(f"heap_gate: sweeping {len(names)} blocks over {len(fixture_paths)} fixtures ...")
    r = subprocess.run(cmd, env=env)
    if r.returncode != 0:
        die(f"killer_sweep.sh exited {r.returncode}", 2)


def read_baseline(gas, backend):
    path = GATE_DIR / f"baseline-{gas}-{backend}.tsv"
    if not path.exists():
        return path, None, {}
    header = {}
    rows = {}
    for line in path.read_text().splitlines():
        if line.startswith("#"):
            m = re.match(r"#\s*(\w+):\s*(.*)", line)
            if m:
                header[m.group(1)] = m.group(2).strip()
            continue
        if not line.strip() or line.startswith("name\t"):
            continue
        f = line.split("\t")
        rows[f[0]] = dict(zip(BASELINE_COLS[1:], f[1:]))
    return path, header, rows


def write_baseline(path, backend, gas, release, elf, metrics):
    heap = heap_bound.heap_bytes(elf)
    lines = [
        f"# backend: {backend}", f"# gas: {gas}", f"# release: {release}",
        f"# seed: {SEED}", f"# heap_bytes: {heap}",
        "# metrics in bytes; see scripts/heap_gate.py / HEAP_BUDGET.md",
        "\t".join(BASELINE_COLS),
    ]
    for name in sorted(metrics):
        m = metrics[name]
        if m is None:
            continue
        lines.append("\t".join(str(x) for x in [
            name, m["in_used"], m["fixed"], m["exec_used"], m["tx_peak"],
            m["gas_used"], m["txs"], m["input"], m["fork"]]))
    path.write_text("\n".join(lines) + "\n")
    print(f"heap_gate: wrote {path} ({sum(1 for v in metrics.values() if v)} blocks)")


def gate(args, names, reasons):
    heap = heap_bound.heap_bytes(args.elf)
    collected = collect(args.out)
    _, _, baseline = read_baseline(args.gas, args.backend)
    if not args.update and not baseline:
        die(f"no baseline for {args.backend}/{args.gas}; create one with HEAP_GATE_UPDATE=1")

    fails = []
    metrics = {}
    worst_ratio = 0.0
    for name in names:
        if name not in collected:
            fails.append(f"MISSING  {name}: not produced by the sweep")
            continue
        m, verdict, oom = collected[name]
        if m is None:
            fails.append(f"HALT     {name}: {oom or 'no HEAP end line'} (verdict {verdict})")
            continue
        if verdict != "PASS":
            fails.append(f"VERDICT  {name}: {verdict}")
        metrics[name] = m
        used = m["in_used"] + m["fixed"] + m["exec_used"]
        # Hard ceiling: used_end + arena peak must stay under a share of the heap.
        if m["used_end"] + m["tx_peak"] > MAX_SHARE * heap:
            fails.append(f"SHARE    {name}: {(m['used_end'] + m['tx_peak']) / 1e6:.1f} MB "
                         f"> {MAX_SHARE:.0%} of {heap / 1e6:.1f} MB")
        # Bound: per-block measured <= modeled bound.
        b = heap_bound.bound(args.backend, m["fork"], gas_used=m["gas_used"],
                             txs=m["txs"], input_bytes=m["input"])
        measured = used + m["tx_peak"]
        worst_ratio = max(worst_ratio, measured / b["required"])
        if measured > b["required"]:
            fails.append(f"BOUND    {name}: {measured / 1e6:.1f} MB > bound {b['required'] / 1e6:.1f} MB")
        # Baseline regression (skipped under --update).
        if baseline and not args.update:
            base = baseline.get(name)
            if base is None:
                fails.append(f"NOBASE   {name}: no baseline row")
                continue
            for key in ("in_used", "exec_used", "tx_peak"):
                b0 = int(base[key])
                if m[key] > b0 + max(b0 * TOL_PCT / 100.0, TOL_ABS):
                    fails.append(f"REGRESS  {name}.{key}: {m[key]} > baseline {b0} "
                                 f"(+{(m[key] - b0) / 1e6:.2f} MB)")
                elif m[key] < b0 - max(b0 * TOL_PCT / 100.0, TOL_ABS):
                    print(f"  IMPROVED {name}.{key}: {m[key]} < baseline {b0} "
                          f"({(m[key] - b0) / 1e6:+.2f} MB) — consider HEAP_GATE_UPDATE=1")
            if abs(m["fixed"] - int(base["fixed"])) > FIXED_TOL:
                fails.append(f"FIXED    {name}: analysis cache {m['fixed']} vs baseline {base['fixed']}")

    print(f"heap_gate: {len(metrics)}/{len(names)} blocks measured, "
          f"worst measured/bound {worst_ratio:.3f}, heap {heap / 1e6:.1f} MB")

    if args.update:
        path = GATE_DIR / f"baseline-{args.gas}-{args.backend}.tsv"
        hard = [f for f in fails if f.split()[0] in ("MISSING", "HALT", "VERDICT", "SHARE", "BOUND")]
        if hard:
            print("\n".join("  " + f for f in hard))
            die("refusing --update: non-baseline checks failed", 1)
        write_baseline(path, args.backend, args.gas, args.release, args.elf, metrics)
        return 0

    if fails:
        print("\nheap_gate FAILURES:")
        print("\n".join("  " + f for f in fails))
        return 1
    print("heap_gate: PASS")
    return 0


def select(args):
    """Print a blocks-<GAS>.txt from a full run (--skip-run --all): the heaviest
    blocks by each metric, no NEG_ blocks."""
    collected = collect(args.out)
    rows = []
    for name, (m, verdict, _oom) in collected.items():
        if m is None or verdict != "PASS":
            continue
        # fixture relpath: from blocks.run field 7 (the fixture path), made
        # relative to the fixtures root.
        rows.append((name, m))
    fixtures = {}
    for line in (Path(args.out) / "blocks.run").read_text().splitlines():
        f = line.split()
        if len(f) >= 8:
            # The fixture path may come from a reused run's p1 (a different
            # absolute root); the gate needs it relative to blockchain_tests/,
            # which is stable across the fixture-set copies.
            marker = "/blockchain_tests/"
            rel = f[6].split(marker, 1)[1] if marker in f[6] else f[6]
            fixtures[f[7]] = rel
    n = args.select
    picked = {}
    for key, reason in (("used_end", "max heap"), ("tx_peak", "max arena"),
                        ("exec_used", "max exec"), ("in_used", "max state-root")):
        for name, m in sorted(rows, key=lambda r: -r[1][key])[:n]:
            picked.setdefault(name, reason)
    print(f"# blocks-{args.gas}.txt — heap-gate block list, {len(picked)} blocks")
    print("# <fixture_relpath>\\t<name>\\t<reason>  (generated by heap_gate.py --select)")
    for name in sorted(picked, key=lambda x: fixtures.get(x, "")):
        print(f"{fixtures.get(name, '?')}\t{name}\t{picked[name]}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=("evmone", "zevm"), required=True)
    ap.add_argument("--gas", default="0200M")
    ap.add_argument("--host", default="")
    ap.add_argument("--elf", default="")
    ap.add_argument("--ziskemu", default=os.environ.get("ZISKEMU", "ziskemu"))
    ap.add_argument("--fixtures", default="")
    ap.add_argument("--release", default="")
    ap.add_argument("-o", "--out", default="")
    ap.add_argument("--jobs", type=int, default=int(os.environ.get("KILLER_JOBS", "3")))
    ap.add_argument("--update", action="store_true",
                    default=os.environ.get("HEAP_GATE_UPDATE") == "1")
    ap.add_argument("--skip-run", action="store_true")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--select", type=int, metavar="N")
    ap.add_argument("--dump", metavar="TSV",
                    help="write every block's metrics in OUT to a TSV (for heap_bound --check)")
    args = ap.parse_args()
    if not args.out:
        args.out = str(REPO_ROOT / "build" / f"heap-gate-{args.gas}-{args.backend}")

    if args.select is not None:
        return select(args)
    if args.dump:
        collected = collect(args.out)
        metrics = {n: m for n, (m, v, _o) in collected.items() if m and v == "PASS"}
        write_baseline(Path(args.dump), args.backend, args.gas, args.release,
                       args.elf or str(REPO_ROOT / f"cpp-guest/zisk/build-heap-mainnet-{args.backend}/zisk_eth_guest.elf"),
                       metrics)
        return 0

    _, fixtures, names, reasons = load_block_list(args.gas)
    if not args.skip_run:
        for need in ("host", "elf", "fixtures"):
            if not getattr(args, need):
                die(f"--{need} required to run the sweep")
        run_sweep(args, names, fixtures)
    return gate(args, names, reasons)


if __name__ == "__main__":
    sys.exit(main())

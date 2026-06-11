#!/usr/bin/env python3
"""Per-block evmone-vs-zevm ZisK-cost comparison.

For each block this:
  1. runs `input-gen` to produce the binary witness (same pipeline as
     `verify_blocks.py`),
  2. frames it for ziskemu (an 8-byte LE length prefix),
  3. runs the witness through BOTH ZisK ELFs (the evmone-backend and the
     zevm-backend `zisk_eth_guest.elf`) under `ziskemu -X`,
  4. checks BOTH reproduce the canonical block hash from the RPC, and
  5. tabulates STEPS + total proving cost and the zevm/evmone ratio.

Unlike the single-guest host run in `verify_blocks.py`, this runs the RISC-V
ELFs on the ZisK emulator, because the comparison we care about is the ZisK
proving cost (steps / cost), not just correctness.

Modes (default = follow chain head, like verify_blocks.py):
  --start-from N --count K   replay K consecutive blocks starting at N
  --blocks N1,N2,...         an explicit comma-separated list

Costs go to stdout as a table and, with --csv PATH, are appended there.
A hash mismatch on either backend is flagged loudly (a cost number is
meaningless if the result is wrong).

Run from anywhere — paths resolve relative to the repo root.
"""

import argparse
import json
import re
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
INPUT_GEN = REPO_ROOT / "target" / "release" / "input-gen"
ZISKEMU = Path.home() / "git" / "zisk" / "zisk" / "target" / "release" / "ziskemu"
# The two ZisK ELFs to compare. Build them with:
#   cmake -S cpp-guest/zisk -B cpp-guest/zisk/build-evmone \
#     -DCMAKE_TOOLCHAIN_FILE=$(pwd)/cpp-guest/zisk/toolchain.cmake \
#     -DCMAKE_BUILD_TYPE=Release -DEVM_BACKEND=evmone   (and =zevm for build-zevm)
#   cmake --build cpp-guest/zisk/build-<be> --target zisk_eth_guest.elf
ELFS = {
    "evmone": REPO_ROOT / "cpp-guest" / "zisk" / "build-evmone" / "zisk_eth_guest.elf",
    "zevm":   REPO_ROOT / "cpp-guest" / "zisk" / "build-zevm"   / "zisk_eth_guest.elf",
}
# Cost categories parsed from `ziskemu -X` (besides STEPS / TOTAL).
CATEGORIES = ["MAIN", "OPCODES", "PRECOMPILES", "MEMORY"]


def rpc(url: str, method: str, params: list, timeout: float = 30.0):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params}).encode()
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.loads(r.read())
    if "error" in body:
        raise RuntimeError(f"RPC {method} error: {body['error']}")
    return body["result"]


def head_block(url: str) -> int:
    return int(rpc(url, "eth_blockNumber", []), 16)


def chain_block(url: str, n: int) -> dict:
    return rpc(url, "eth_getBlockByNumber", [hex(n), False], timeout=60.0)


def run_input_gen(url: str, block: int, out_path: Path, log_path: Path,
                  timeout: float) -> int:
    cmd = [str(INPUT_GEN), "--rpc-url", url, "--block", str(block),
           "--output", str(out_path)]
    with log_path.open("wb") as f:
        f.write(("$ " + " ".join(cmd) + "\n").encode())
        f.flush()
        try:
            return subprocess.call(cmd, stdout=f, stderr=subprocess.STDOUT,
                                   cwd=str(REPO_ROOT), timeout=timeout)
        except subprocess.TimeoutExpired:
            f.write(b"\n[compare_backends.py] input-gen timed out\n")
            return 124


def frame_for_ziskemu(raw: Path, framed: Path) -> None:
    """Prepend the 8-byte LE length header ziskemu expects."""
    data = raw.read_bytes()
    with framed.open("wb") as f:
        f.write(struct.pack("<Q", len(data)))
        f.write(data)


def run_ziskemu(elf: Path, framed_input: Path, out_bin: Path,
                timeout: float) -> Optional[dict]:
    """Run one ELF under ziskemu -X. Returns {steps,total,<cats>,hash} or None."""
    cmd = [str(ZISKEMU), "-e", str(elf), "-i", str(framed_input),
           "-o", str(out_bin), "-X"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    if p.returncode != 0:
        return None
    out = {}
    for line in p.stdout.splitlines():
        m = re.match(r"^(STEPS|TOTAL|" + "|".join(CATEGORIES) + r")\s+([\d,]+)", line)
        if m:
            out[m.group(1)] = int(m.group(2).replace(",", ""))
    try:
        out["hash"] = "0x" + out_bin.read_bytes()[:32].hex()
    except OSError:
        out["hash"] = None
    if "STEPS" not in out or "TOTAL" not in out:
        return None
    return out


def fmt(n: int) -> str:
    return f"{n:,}"


def gas_h(g: int) -> str:
    return f"{g / 1e6:.1f}M"


def process_block(url: str, block: int, art_dir: Path, args) -> Optional[dict]:
    """Run both backends on `block`. Returns a result dict or None on a setup error."""
    art_dir.mkdir(parents=True, exist_ok=True)
    raw = art_dir / "input.bin"
    framed = art_dir / "input.zisk.bin"
    ig_log = art_dir / "input-gen.log"

    try:
        cb = chain_block(url, block)
    except Exception as e:
        print(f"[err]  block {block}: eth_getBlockByNumber failed: {e}", file=sys.stderr)
        return None
    chain_hash = cb["hash"].lower()
    gas = int(cb["gasUsed"], 16)
    ntx = len(cb["transactions"])

    ig_rc = run_input_gen(url, block, raw, ig_log, args.input_gen_timeout)
    if ig_rc != 0:
        print(f"[FAIL] block {block}: input-gen exited {ig_rc} "
              f"(see {ig_log.relative_to(REPO_ROOT)})", file=sys.stderr)
        return None
    frame_for_ziskemu(raw, framed)

    res = {"block": block, "gas": gas, "ntx": ntx, "chain_hash": chain_hash,
           "backends": {}}
    for be, elf in ELFS.items():
        if not elf.exists():
            sys.exit(f"{be} ELF not found at {elf} — build it (see header comment).")
        r = run_ziskemu(elf, framed, art_dir / f"out.{be}.bin", args.ziskemu_timeout)
        if r is None:
            print(f"[FAIL] block {block}: ziskemu/{be} run failed", file=sys.stderr)
            return None
        r["ok"] = (r["hash"] == chain_hash)
        res["backends"][be] = r

    if args.keep_artifacts is False:
        for p in (raw, framed, art_dir / "out.evmone.bin", art_dir / "out.zevm.bin"):
            p.unlink(missing_ok=True)
    return res


def print_row(res: dict, header_done: list, csv_f):
    z = res["backends"]["zevm"]
    e = res["backends"]["evmone"]
    ratio = z["STEPS"] / e["STEPS"] if e["STEPS"] else float("nan")
    cratio = z["TOTAL"] / e["TOTAL"] if e["TOTAL"] else float("nan")
    hashes = ("OK" if (z["ok"] and e["ok"]) else
              f"MISMATCH(z={'ok' if z['ok'] else 'BAD'},e={'ok' if e['ok'] else 'BAD'})")
    if not header_done:
        print(f"{'block':>9} {'gas':>7} {'txs':>4} | "
              f"{'zevm steps':>14} {'evmone steps':>14} {'ratio':>6} | "
              f"{'zevm cost':>17} {'evmone cost':>17} {'cost×':>6} | hashes")
        print("-" * 120)
        header_done.append(True)
    print(f"{res['block']:>9} {gas_h(res['gas']):>7} {res['ntx']:>4} | "
          f"{fmt(z['STEPS']):>14} {fmt(e['STEPS']):>14} {ratio:>5.2f}x | "
          f"{fmt(z['TOTAL']):>17} {fmt(e['TOTAL']):>17} {cratio:>5.2f}x | {hashes}")
    if csv_f:
        if csv_f.tell() == 0:
            cols = (["block", "gas", "txs", "steps_ratio", "cost_ratio", "hashes_ok"]
                    + [f"{be}_{k}" for be in ELFS for k in
                       ["steps", "total"] + CATEGORIES])
            csv_f.write(",".join(cols) + "\n")
        row = [res["block"], res["gas"], res["ntx"], f"{ratio:.4f}",
               f"{cratio:.4f}", int(z["ok"] and e["ok"])]
        for be in ELFS:
            b = res["backends"][be]
            row += [b["STEPS"], b["TOTAL"]] + [b.get(c, "") for c in CATEGORIES]
        csv_f.write(",".join(str(x) for x in row) + "\n")
        csv_f.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpc-url", default="http://localhost:8545")
    ap.add_argument("--start-from", type=int, default=None,
                    help="First block of a replay range")
    ap.add_argument("--count", type=int, default=1,
                    help="Number of blocks to replay from --start-from (default 1)")
    ap.add_argument("--blocks", default=None,
                    help="Explicit comma-separated block list (overrides --start-from)")
    ap.add_argument("--poll-sec", type=float, default=5.0,
                    help="Head-follow poll interval (when no range/list given)")
    ap.add_argument("--input-gen-timeout", type=float, default=600.0)
    ap.add_argument("--ziskemu-timeout", type=float, default=1800.0)
    ap.add_argument("--csv", type=Path, default=None,
                    help="Append per-block rows (incl. category breakdown) here")
    ap.add_argument("--keep-artifacts", action="store_true",
                    help="Keep per-block input/output bins under build/compare/<N>/")
    args = ap.parse_args()

    if not ZISKEMU.exists():
        sys.exit(f"ziskemu not found at {ZISKEMU}")
    if not INPUT_GEN.exists():
        sys.exit(f"input-gen not built at {INPUT_GEN} "
                 "(cargo build --release --manifest-path rust-input-gen/Cargo.toml)")

    # Resolve the block sequence.
    if args.blocks:
        targets = [int(x) for x in args.blocks.split(",") if x.strip()]
        follow = False
    elif args.start_from is not None:
        targets = list(range(args.start_from, args.start_from + args.count))
        follow = False
    else:
        targets = None  # follow head
        follow = True

    csv_f = args.csv.open("a") if args.csv else None
    header_done: list = []
    ratios: list[float] = []

    def handle(block: int):
        art = REPO_ROOT / "build" / "compare" / str(block)
        res = process_block(args.rpc_url, block, art, args)
        if res:
            print_row(res, header_done, csv_f)
            e = res["backends"]["evmone"]["STEPS"]
            if e:
                ratios.append(res["backends"]["zevm"]["STEPS"] / e)

    try:
        if follow:
            print(f"[start] following head on {args.rpc_url}", file=sys.stderr)
            last = head_block(args.rpc_url)
            while True:
                try:
                    h = head_block(args.rpc_url)
                except (urllib.error.URLError, RuntimeError) as ex:
                    print(f"[warn] poll: {ex}", file=sys.stderr)
                    time.sleep(args.poll_sec); continue
                if h <= last:
                    time.sleep(args.poll_sec); continue
                for b in range(last + 1, h + 1):
                    handle(b)
                last = h
        else:
            for b in targets:
                handle(b)
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)

    if ratios:
        gm = 1.0
        for r in ratios:
            gm *= r
        gm **= (1.0 / len(ratios))
        print("-" * 120)
        print(f"[summary] {len(ratios)} blocks — zevm/evmone steps: "
              f"min {min(ratios):.2f}x, max {max(ratios):.2f}x, geomean {gm:.2f}x")
    if csv_f:
        csv_f.close()


if __name__ == "__main__":
    main()

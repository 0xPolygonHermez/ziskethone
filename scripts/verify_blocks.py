#!/usr/bin/env python3
"""Continuous block-hash verifier for the zisk-eth-guest pipeline.

Polls a local Ethereum RPC for new blocks. For each new head it (1) runs
`rust-input-gen` to produce the binary witness, (2) runs the `cpp-guest`
binary on that witness, and (3) compares the cpp-guest's computed block
hash against the canonical hash reported by the RPC.

On any failure (input-gen non-zero exit, cpp-guest crash, or hash
mismatch) the per-block artifacts are written under `build/verify/<N>/`,
a `failure.md` is emitted with a ready-to-paste debug prompt, and an
interactive `claude` session is spawned at the repo root. After `claude`
exits the user is asked whether to resume.

Run from anywhere — paths are resolved relative to the repo root that
contains this script's parent directory.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
INPUT_GEN_MANIFEST = REPO_ROOT / "rust-input-gen" / "Cargo.toml"
GUEST_BIN = REPO_ROOT / "cpp-guest" / "build" / "zisk_eth_guest"


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
    """Returns exit code. Combined stdout+stderr -> log_path."""
    cmd = [
        "cargo", "run", "--release",
        "--manifest-path", str(INPUT_GEN_MANIFEST),
        "--bin", "input-gen",
        "--",
        "--rpc-url", url,
        "--block", str(block),
        "--output", str(out_path),
    ]
    with log_path.open("wb") as f:
        f.write(("$ " + " ".join(cmd) + "\n").encode())
        f.flush()
        try:
            return subprocess.call(cmd, stdout=f, stderr=subprocess.STDOUT,
                                   cwd=str(REPO_ROOT), timeout=timeout)
        except subprocess.TimeoutExpired:
            f.write(b"\n[verify_blocks.py] input-gen timed out\n")
            return 124


def run_guest(input_bin: Path, stdout_path: Path, stderr_path: Path,
              timeout: float) -> int:
    cmd = [str(GUEST_BIN), str(input_bin)]
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        try:
            return subprocess.call(cmd, stdout=out, stderr=err, timeout=timeout)
        except subprocess.TimeoutExpired:
            err.write(b"\n[verify_blocks.py] cpp-guest timed out\n")
            return 124


def read_cpp_hash(stdout_path: Path) -> Optional[str]:
    """Return the first `0x<64hex>` line of cpp-guest's stdout, or None."""
    try:
        with stdout_path.open("r") as f:
            for line in f:
                s = line.strip()
                if s.startswith("0x") and len(s) == 66:
                    try:
                        int(s, 16)
                        return s.lower()
                    except ValueError:
                        continue
    except FileNotFoundError:
        pass
    return None


def write_failure(art_dir: Path, kind: str, block: int, chain_hash: Optional[str],
                  cpp_hash: Optional[str], parent_hash: Optional[str], head: int,
                  extra: str = "") -> Path:
    md = art_dir / "failure.md"
    suggested = (
        f"Please help me debug a {kind} on block {block}. Artifacts are in "
        f"`{art_dir.relative_to(REPO_ROOT)}/`. Start by reading "
        f"`{md.relative_to(REPO_ROOT)}`."
    )
    lines = [
        "# Verification failure",
        "",
        "## Suggested first prompt for this Claude session",
        "",
        "```",
        suggested,
        "```",
        "",
        "## Details",
        "",
        f"- kind: **{kind}**",
        f"- block: **{block}**",
        f"- head at run time: {head}",
        f"- chain block hash: `{chain_hash or '—'}`",
        f"- cpp-guest hash:   `{cpp_hash or '—'}`",
        f"- parent hash:      `{parent_hash or '—'}`",
        "",
        "## Artifacts",
        "",
        f"- input file:     `{(art_dir / 'input.bin').relative_to(REPO_ROOT)}`",
        f"- input-gen log:  `{(art_dir / 'input-gen.log').relative_to(REPO_ROOT)}`",
        f"- cpp-guest out:  `{(art_dir / 'cpp-stdout.txt').relative_to(REPO_ROOT)}`",
        f"- cpp-guest err:  `{(art_dir / 'cpp-stderr.txt').relative_to(REPO_ROOT)}`",
        f"- chain block:    `{(art_dir / 'chain.json').relative_to(REPO_ROOT)}`",
    ]
    if extra:
        lines += ["", "## Extra", "", extra]
    md.write_text("\n".join(lines) + "\n")
    return md


def prompt_continue() -> bool:
    try:
        ans = input("Continue verifying next blocks? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("", "y", "yes")


def wait_for_new_block(url: str, last: int, poll_sec: float) -> int:
    """Block until head > last. Returns the new head."""
    while True:
        try:
            h = head_block(url)
            if h > last:
                return h
        except (urllib.error.URLError, RuntimeError) as e:
            print(f"[warn] RPC poll failed: {e}", file=sys.stderr)
        time.sleep(poll_sec)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rpc-url", default="http://localhost:8545")
    ap.add_argument("--poll-sec", type=float, default=5.0)
    ap.add_argument("--start-from", type=int, default=None,
                    help="Replay from this block (default: head+1 at startup)")
    ap.add_argument("--input-gen-timeout", type=float, default=600.0)
    ap.add_argument("--guest-timeout", type=float, default=300.0)
    ap.add_argument("--no-claude", action="store_true",
                    help="Skip spawning claude on failure")
    args = ap.parse_args()

    if not GUEST_BIN.exists():
        sys.exit(f"cpp-guest binary not found at {GUEST_BIN} "
                 "(did you run `make cpp`?)")

    # Resolve starting block.
    initial_head = head_block(args.rpc_url)
    if args.start_from is not None:
        last_processed = args.start_from - 1
        print(f"[start] head={initial_head} replaying from {args.start_from}")
    else:
        last_processed = initial_head
        print(f"[start] head={initial_head} waiting for next block")

    # Make Ctrl-C during idle polling exit cleanly. During subprocesses
    # we restore the default handler so SIGINT propagates to the child.
    def on_sigint(signum, frame):
        print("\nStopped.")
        sys.exit(0)
    signal.signal(signal.SIGINT, on_sigint)

    # Per-block reorg-retry counter. input-gen exits 75 (EX_TEMPFAIL)
    # when it detects the node reorged mid-run; we just re-queue the
    # same target. Cap retries so a chronically-flapping node doesn't
    # spin forever.
    REORG_EXIT_CODE = 75
    MAX_REORG_RETRIES = 5
    reorg_retries: dict[int, int] = {}

    while True:
        try:
            target = wait_for_new_block(args.rpc_url, last_processed,
                                        args.poll_sec)
        except KeyboardInterrupt:
            print("\nStopped.")
            return 0

        art_dir = REPO_ROOT / "build" / "verify" / str(target)
        art_dir.mkdir(parents=True, exist_ok=True)
        input_bin = art_dir / "input.bin"
        input_log = art_dir / "input-gen.log"
        cpp_out = art_dir / "cpp-stdout.txt"
        cpp_err = art_dir / "cpp-stderr.txt"
        chain_path = art_dir / "chain.json"

        print(f"[run]  block {target} → {art_dir.relative_to(REPO_ROOT)}")

        # Fetch chain hash first so we have a reference even if generation
        # crashes mid-run.
        try:
            chain_b = chain_block(args.rpc_url, target)
        except Exception as e:
            print(f"[err]  eth_getBlockByNumber({target}) failed: {e}",
                  file=sys.stderr)
            # Wait for the next block; this one is unrecoverable.
            last_processed = target
            continue
        chain_path.write_text(json.dumps(chain_b, indent=2))
        chain_hash = chain_b["hash"].lower()
        parent_hash = chain_b["parentHash"].lower()

        # 1) input-gen
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        ig_rc = run_input_gen(args.rpc_url, target, input_bin, input_log,
                              args.input_gen_timeout)
        signal.signal(signal.SIGINT, on_sigint)
        # Reorg-class failure: input-gen detected a mid-run reorg.
        # Re-queue the block (do NOT advance last_processed, do NOT
        # write a failure artifact), with a small backoff. Capped to
        # avoid a hot-spin if the node is constantly reorging.
        if ig_rc == REORG_EXIT_CODE:
            retries = reorg_retries.get(target, 0) + 1
            if retries <= MAX_REORG_RETRIES:
                reorg_retries[target] = retries
                print(f"[reorg] block {target} — chain reorged mid-run "
                      f"(retry {retries}/{MAX_REORG_RETRIES}), waiting...")
                time.sleep(args.poll_sec)
                continue
            # Out of retries — fall through to normal failure handling.
            reorg_retries.pop(target, None)
            print(f"[reorg] block {target} — exceeded {MAX_REORG_RETRIES} "
                  f"retries, recording as failure.", file=sys.stderr)
        # Successful (or terminal-fail) input-gen: clear any retry
        # counter so a future re-encounter starts fresh.
        reorg_retries.pop(target, None)
        if ig_rc != 0:
            md = write_failure(art_dir, "INPUT-GEN-FAIL", target, chain_hash,
                               None, parent_hash, head_block(args.rpc_url),
                               extra=f"input-gen exited with code {ig_rc}.")
            failure_path = md
            failure_kind = "INPUT-GEN-FAIL"
        else:
            # 2) cpp-guest
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            g_rc = run_guest(input_bin, cpp_out, cpp_err, args.guest_timeout)
            signal.signal(signal.SIGINT, on_sigint)
            cpp_hash = read_cpp_hash(cpp_out)
            if g_rc != 0:
                md = write_failure(art_dir, "GUEST-CRASH", target, chain_hash,
                                   cpp_hash, parent_hash,
                                   head_block(args.rpc_url),
                                   extra=f"cpp-guest exited with code {g_rc}.")
                failure_path = md
                failure_kind = "GUEST-CRASH"
            elif cpp_hash is None:
                md = write_failure(art_dir, "GUEST-CRASH", target, chain_hash,
                                   None, parent_hash, head_block(args.rpc_url),
                                   extra="cpp-guest exited 0 but produced no "
                                         "block-hash line on stdout.")
                failure_path = md
                failure_kind = "GUEST-CRASH"
            elif cpp_hash != chain_hash:
                # Reorg check before declaring a real mismatch.
                # `chain_hash` was snapshotted before input-gen ran;
                # if the chain reorged in between, cpp_hash may match
                # the NEW canonical block at `target` even though the
                # stale chain.json shows the orphaned one. Re-fetch
                # and compare. If still a mismatch — real bug.
                try:
                    fresh_b = chain_block(args.rpc_url, target)
                    fresh_hash = fresh_b["hash"].lower()
                except Exception as e:
                    print(f"[warn] reorg recheck failed: {e}", file=sys.stderr)
                    fresh_hash = chain_hash  # treat as unchanged
                if fresh_hash != chain_hash:
                    # Reorg happened — refresh the stored chain.json
                    # so the artifact reflects current chain state,
                    # then re-compare.
                    chain_b   = fresh_b
                    chain_hash  = fresh_hash
                    parent_hash = chain_b["parentHash"].lower()
                    chain_path.write_text(json.dumps(chain_b, indent=2))
                if cpp_hash == chain_hash:
                    print(f"[OK]   block {target} hash={cpp_hash} "
                          f"(after chain.json refresh for reorg)")
                    last_processed = target
                    continue
                md = write_failure(art_dir, "HASH-MISMATCH", target, chain_hash,
                                   cpp_hash, parent_hash,
                                   head_block(args.rpc_url))
                failure_path = md
                failure_kind = "HASH-MISMATCH"
            else:
                print(f"[OK]   block {target} hash={cpp_hash}")
                last_processed = target
                continue

        # Failure path (any kind).
        print(f"[FAIL] block {target} kind={failure_kind} "
              f"see {failure_path.relative_to(REPO_ROOT)}")
        if args.no_claude:
            last_processed = target
            continue

        print(f"       spawning `claude` in {REPO_ROOT}...")
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        try:
            subprocess.call(["claude"], cwd=str(REPO_ROOT))
        except FileNotFoundError:
            print("[warn] `claude` not on PATH — skipping spawn",
                  file=sys.stderr)
        signal.signal(signal.SIGINT, on_sigint)

        if not prompt_continue():
            return 0
        last_processed = target


if __name__ == "__main__":
    main()

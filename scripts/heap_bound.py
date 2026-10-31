#!/usr/bin/env python3
"""Worst-case heap bound for the ZisK guest (see HEAP_BUDGET.md).

The guest runs under a bump allocator that never frees plus a per-transaction
arena that is reset each transaction and system call (cpp-guest/zisk/runtime.cpp).
This tool composes, from a table of allocation sites, the most heap a valid block
can make the guest hold, and checks it against the ELF's actual heap size.

The model, per backend and fork:

    heap_total = fixed            # analysis cache (never reset)
               + txs * per_tx     # ~3 KB of trie/receipt/parse state per tx
               + gas * gas_rate   # every per-gas heap consumer, summed
    arena      = max single-tx arena peak   # bounded by one tx's regular gas
    required   = heap_total + arena   <=   heap_bytes(ELF)

`gas` is the gas available to the heap-growing dimension of the block: regular
gas for Amsterdam (EIP-8037 state gas is refunded and cannot pay for heap), the
block gas for earlier forks; Osaka refunds let spent gas reach 1.25x gasUsed.

Input size is NOT an independent term. Witness nodes and codes are viewed in the
input region, not copied; the heap rows that index them exist only for state the
block TOUCHED, which costs cold-access gas (a cold key ~2100 gas -> ~1.2 KB), so
that heap is already inside gas_rate. A block whose witness exceeds the 2 GiB
input region fails to load at all — the S3 ceiling, an operator-side limit
(larger region or input metering), not a guest heap bound; HEAP_BUDGET.md tracks
it separately.

Rates live in scripts/heap_gate/sites.tsv (one row per site, with citations);
HEAP_BUDGET.md is generated from it. Until that table is complete the built-in
DEFAULTS below are used — deliberately conservative (an over-estimate is a
weaker bound, never a false pass), and validated to exceed every measured block.

Usage:
    heap_bound.py --backend evmone --chain sepolia --elf <elf>   # does it fit?
    heap_bound.py --backend evmone --chain all --elf <elf>
    heap_bound.py --check measured.tsv --backend evmone --elf <elf>
Exit: 0 fits / all rows under bound, 1 does not fit or a check failed, 2 usage.
"""

import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Fork -> gas-dimension multiplier over gasUsed (how much gas can actually be
# spent growing the heap, relative to the header's gasUsed).
#   Amsterdam: gasUsed = max(regular, state); heap grows with regular gas, which
#     is <= gasUsed, and state gas is refunded, so 1.0.
#   Osaka and earlier: gasUsed is post-refund; spent gas <= 1.25x gasUsed.
CHAINS = {
    # chain:    (fork name, block gas limit, max input bytes, per-tx regular cap, syscall gas, syscalls)
    "mainnet": ("Osaka", 60_000_000, 2 << 30, 1 << 24, 30_000_000, 4),
    "sepolia": ("Amsterdam", 200_000_000, 2 << 30, 1 << 24, 30_000_000, 6),
}
REFUND_FACTOR = {"Amsterdam": 1.0, "Osaka": 1.25, "Prague": 1.25, "Cancun": 1.25}

# Conservative built-in rates until sites.tsv is complete (step 6 of the plan).
# Bytes unless noted. Sourced from the allocation-site inventory; see
# HEAP_BUDGET.md for the per-site derivation and citations.
# gas_rate is the MAX single per-gas heap consumer (B per gas), not a sum: each
# gas unit is spent once, so the heap it can create is bounded by the costliest
# way to spend it — witness rows for cold keys ~0.57 (a cold key ~2100 gas ->
# ~1.2 KB), above surviving logs ~0.375 and warm-key dead nodes ~0.3. 0.70
# leaves margin; step 6 replaces it with per-site rows in sites.tsv.
DEFAULTS = {
    "evmone": {
        "fixed": 85_072_992,     # analysis cache: 1152 * 73808 + meta + object
        "gas_rate": 0.70,        # max per-gas heap consumer (cold-key witness) + margin
        "per_tx": 3200,          # parse + receipts-trie + header/NPR state per tx
        "arena": 70_000_000,     # deepest single-tx arena (recursive memory growth)
    },
    "zevm": {
        "fixed": 9_483_360,      # analysis cache: 1152 * 8192 + meta + object
        "gas_rate": 0.70,
        "per_tx": 3200,
        "arena": 40_000_000,     # zevm EVM memory is static; arena holds journal/transient
    },
}


def heap_bytes(elf_path):
    """Heap size from the ELF: _heap_end - _heap_start (zisk.ld). Pure ELF64
    symtab parse, so no toolchain nm is needed for a RISC-V target."""
    data = Path(elf_path).read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError(f"{elf_path}: not an ELF64 file")
    le = "<" if data[5] == 1 else ">"
    e_shoff = struct.unpack_from(le + "Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from(le + "H", data, 0x3A)[0]
    e_shnum = struct.unpack_from(le + "H", data, 0x3C)[0]
    symtab = strtab = None
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_type = struct.unpack_from(le + "I", data, off + 4)[0]
        if sh_type == 2:  # SHT_SYMTAB
            sh_offset = struct.unpack_from(le + "Q", data, off + 0x18)[0]
            sh_size = struct.unpack_from(le + "Q", data, off + 0x20)[0]
            sh_link = struct.unpack_from(le + "I", data, off + 0x28)[0]
            sh_entsize = struct.unpack_from(le + "Q", data, off + 0x38)[0]
            symtab = (sh_offset, sh_size, sh_entsize)
            link_off = e_shoff + sh_link * e_shentsize
            strtab = (
                struct.unpack_from(le + "Q", data, link_off + 0x18)[0],
                struct.unpack_from(le + "Q", data, link_off + 0x20)[0],
            )
    if symtab is None:
        raise ValueError(f"{elf_path}: no symbol table")
    sym_off, sym_size, sym_entsize = symtab
    str_off, str_size = strtab
    syms = {}
    for off in range(sym_off, sym_off + sym_size, sym_entsize):
        st_name = struct.unpack_from(le + "I", data, off)[0]
        st_value = struct.unpack_from(le + "Q", data, off + 8)[0]
        end = data.index(b"\x00", str_off + st_name)
        name = data[str_off + st_name:end].decode("ascii", "replace")
        if name in ("_heap_start", "_heap_end", "_heap_bottom", "_heap_top"):
            syms[name] = st_value
    start = syms.get("_heap_start", syms.get("_heap_bottom"))
    end = syms.get("_heap_end", syms.get("_heap_top"))
    if start is None or end is None:
        raise ValueError(f"{elf_path}: missing _heap_start/_heap_end symbols")
    return end - start


def load_sites():
    """Site rates from scripts/heap_gate/sites.tsv when present, else DEFAULTS.
    The TSV has a header row and columns: backend, site, lifetime, resource,
    bytes_per_unit, citation. Rates are summed per (backend, resource)."""
    path = REPO_ROOT / "scripts" / "heap_gate" / "sites.tsv"
    if not path.exists():
        return None
    agg = {b: {"fixed": 0.0, "gas_rate": 0.0, "per_tx": 0.0, "arena": 0.0}
           for b in ("evmone", "zevm")}
    resource_key = {"fixed": "fixed", "gas": "gas_rate", "tx": "per_tx", "arena": "arena"}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("backend\t"):
            continue
        f = line.split("\t")
        backend, _site, _life, resource, rate = f[0], f[1], f[2], f[3], float(f[4])
        for b in (("evmone", "zevm") if backend == "both" else (backend,)):
            # gas is a max (one gas unit is spent once); fixed/tx/arena sum.
            key = resource_key[resource]
            if key == "gas_rate":
                agg[b][key] = max(agg[b][key], rate)
            else:
                agg[b][key] += rate
    return agg


def model(backend):
    sites = load_sites()
    return (sites or {})[backend] if sites else DEFAULTS[backend]


def bound(backend, fork, *, gas_used, txs, input_bytes=0, block_gas=None):
    """Required heap (heap_total + arena) for a block, and its parts.
    `input_bytes` is accepted for the record but not an independent term (see
    the module docstring)."""
    m = model(backend)
    gas = gas_used if block_gas is None else block_gas
    gas *= REFUND_FACTOR.get(fork, 1.0)
    fixed = m["fixed"]
    tx = txs * m["per_tx"]
    g = gas * m["gas_rate"]
    heap_total = fixed + tx + g
    return {
        "fixed": fixed, "tx": tx, "gas": g,
        "heap_total": heap_total, "arena": m["arena"],
        "required": heap_total + m["arena"],
    }


def worst_block(backend, chain):
    """The budget at a chain's worst case: the full gas limit spent at the max
    per-gas heap rate, plus as many minimum-gas txs as the gas limit allows
    (both bounds counted, though they cannot peak together — conservative)."""
    fork, gas_limit, _max_input, _tx_cap, _sysgas, nsys = CHAINS[chain]
    min_tx_gas = 12_000 if fork == "Amsterdam" else 21_000
    txs = gas_limit // min_tx_gas
    b = bound(backend, fork, gas_used=gas_limit, txs=txs, block_gas=gas_limit)
    b["syscalls"] = nsys
    return b


def human(n):
    return f"{n / 1e6:.1f} MB" if abs(n) >= 1e6 else f"{n / 1e3:.1f} KB"


def report(backend, chain, heap):
    fork = CHAINS[chain][0]
    b = worst_block(backend, chain)
    print(f"  {chain:8s} ({fork}):")
    for k in ("fixed", "tx", "gas", "arena"):
        print(f"      {k:10s} {human(b[k]):>12s}")
    req, margin = b["required"], heap - b["required"]
    ok = margin >= 0
    print(f"      {'required':10s} {human(req):>12s}  vs heap {human(heap)}"
          f"  -> margin {human(margin)} {'OK' if ok else 'OVER BUDGET'}")
    return ok


def check_rows(tsv_path, backend, heap):
    """Every measured block (a heap_gate TSV) must sit under its own bound."""
    ok = True
    worst_ratio = 0.0
    for line in Path(tsv_path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("name\t"):
            continue
        f = line.split("\t")
        name = f[0]
        in_used, fixed, exec_used, tx_peak = (int(f[i]) for i in (1, 2, 3, 4))
        gas_used, txs, input_bytes = (int(f[i]) for i in (5, 6, 7))
        fork = f[8] if len(f) > 8 else "Amsterdam"
        used = in_used + fixed + exec_used
        b = bound(backend, fork, gas_used=gas_used, txs=txs, input_bytes=input_bytes)
        measured = used + tx_peak
        ratio = measured / b["required"]
        worst_ratio = max(worst_ratio, ratio)
        if measured > b["required"]:
            print(f"  OVER BOUND {name}: measured {human(measured)} > bound {human(b['required'])}")
            ok = False
        if used + tx_peak > heap:
            print(f"  OVER HEAP  {name}: {human(used + tx_peak)} > heap {human(heap)}")
            ok = False
    print(f"  worst measured/bound ratio: {worst_ratio:.3f}")
    return ok


# static_asserts tagged `// heap-budget: <id>` that must exist, with the value
# the model relies on. The assert fails at compile time if a size changes; this
# catches an assert being dropped or renamed, and ties the ids to the doc.
EXPECTED_SIZES = {
    "trie-child": 8, "trie-aux": 88, "trie-branch": 224, "trie-chain": 136,
    "log-entry": 72, "tx-receipt": 344, "journal-entry": 96,
    "account-record": 128, "storage-record": 88,
    "evmone-analysis-slot": 73808, "zevm-analysis-slot": 8192,
}


def sites_table_md():
    """Render sites.tsv as the markdown table embedded in HEAP_BUDGET.md."""
    path = REPO_ROOT / "scripts" / "heap_gate" / "sites.tsv"
    out = ["| backend | site | lifetime | resource | bytes/unit | source |",
           "|---|---|---|---|---:|---|"]
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#") or line.startswith("backend\t"):
            continue
        b, s, life, res, by, cit = line.split("\t")
        out.append(f"| {b} | `{s}` | {life} | {res} | {by} | {cit} |")
    return "\n".join(out)


def self_check():
    """Doc table in sync, tagged static_asserts present with the right values,
    and cited files exist. Returns True on success."""
    ok = True
    # 1. Doc table matches sites.tsv.
    doc = (REPO_ROOT / "HEAP_BUDGET.md").read_text()
    m = re.search(r"<!-- sites:begin -->\n(.*?)\n<!-- sites:end -->", doc, re.S)
    if not m:
        print("  self-check: no <!-- sites:begin/end --> markers in HEAP_BUDGET.md"); ok = False
    elif m.group(1).strip() != sites_table_md().strip():
        print("  self-check: HEAP_BUDGET.md sites table is stale vs sites.tsv"); ok = False
    # 2. Tagged static_asserts present with the expected values.
    grep = subprocess.run(["grep", "-rn", "heap-budget:", str(REPO_ROOT / "cpp-guest")],
                          capture_output=True, text=True)
    found = {}
    for line in grep.stdout.splitlines():
        tag = re.search(r"heap-budget:\s*([\w-]+)", line)
        num = re.search(r"==\s*(\d+)", line)
        if tag:
            found[tag.group(1)] = int(num.group(1)) if num else None
    for tag, val in EXPECTED_SIZES.items():
        if tag not in found:
            print(f"  self-check: missing static_assert tag heap-budget:{tag}"); ok = False
        elif found[tag] is not None and found[tag] != val:
            print(f"  self-check: {tag} asserts {found[tag]}, expected {val}"); ok = False
    # 3. Cited source files exist.
    sites = (REPO_ROOT / "scripts" / "heap_gate" / "sites.tsv").read_text()
    for cited in re.findall(r"([\w./-]+\.(?:cpp|hpp))", sites):
        hits = list((REPO_ROOT / "cpp-guest").rglob(Path(cited).name))
        if not hits:
            print(f"  self-check: cited file not found: {cited}"); ok = False
    print("  self-check: " + ("OK" if ok else "FAILED"))
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=("evmone", "zevm"), required=True)
    ap.add_argument("--chain", choices=("mainnet", "sepolia", "all"))
    ap.add_argument("--elf", help="ELF to read the heap size from")
    ap.add_argument("--heap-bytes", type=int, help="override the heap size")
    ap.add_argument("--check", help="a heap_gate measured TSV; check every row under bound")
    ap.add_argument("--self-check", action="store_true",
                    help="doc table, tagged static_asserts, and citations are current")
    args = ap.parse_args()

    if args.self_check and not (args.chain or args.check):
        print("self-check:")
        return 0 if self_check() else 1

    if args.heap_bytes is not None:
        heap = args.heap_bytes
    elif args.elf:
        heap = heap_bytes(args.elf)
    else:
        ap.error("need --elf or --heap-bytes")
    print(f"heap size ({args.backend}): {human(heap)} ({heap} B)")

    ok = True
    if args.self_check:
        print("self-check:")
        ok &= self_check()
    if args.check:
        print(f"checking {args.check}:")
        ok &= check_rows(args.check, args.backend, heap)
    if args.chain:
        chains = ("mainnet", "sepolia") if args.chain == "all" else (args.chain,)
        for c in chains:
            ok &= report(args.backend, c, heap)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

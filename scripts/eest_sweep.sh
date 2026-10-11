#!/bin/bash
# EEST blockchain-test sweep: bridge every fixture under the given paths
# through eest-witness-gen → input-gen-from-manifest → zisk_eth_guest and
# classify each block (see README "Sweeping a full corpus" for the
# categories).
#
#   scripts/eest_sweep.sh [-g GUEST] [-o OUT] [-j JOBS] PATH...
#
# PATH is a fixture file or a directory (searched for *.json), e.g. one
# EIP's directory:
#   scripts/eest_sweep.sh \
#     /tmp/eest-v21/fixtures/blockchain_tests/for_amsterdam/amsterdam/eip7843_slotnum
#
# Writes one line per block to OUT/results.log (default
# build/eest-sweep/results.log) and prints a tally, overall and per
# fixture directory.
set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
GUEST="$REPO/cpp-guest/build/zisk_eth_guest"
OUT="$REPO/build/eest-sweep"
JOBS=$(nproc)
while getopts "g:o:j:" opt; do
    case $opt in
        g) GUEST=$(realpath "$OPTARG") ;;
        o) OUT=$(realpath -m "$OPTARG") ;;
        j) JOBS=$OPTARG ;;
        *) exit 2 ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || { sed -n 2,17p "$0"; exit 2; }

BRIDGE="$REPO/eest-witness-gen/target/release/eest-witness-gen"
INPUTGEN="$REPO/target/release/input-gen-from-manifest"
for b in "$BRIDGE" "$INPUTGEN" "$GUEST"; do
    [ -x "$b" ] || { echo "missing binary: $b" >&2; exit 1; }
done

rm -rf "$OUT"; mkdir -p "$OUT/work" "$OUT/results"

# One fixture: every block gets exactly one result line.
run_fixture() {
    local FIX="$1"
    local ID; ID=$(echo "$FIX" | md5sum | cut -d' ' -f1)
    local WORK="$OUT/work/fix.$ID" LOG="$OUT/results/$ID.log"
    rm -rf "$WORK"; mkdir -p "$WORK"

    if ! "$BRIDGE" --fixture "$FIX" --output-dir "$WORK" >"$WORK/bridge.log" 2>&1; then
        echo "BRIDGE_FAIL $FIX" >> "$LOG"   # other tests' manifests still run
    fi

    local m
    for m in $(find "$WORK" -name "block-*.json" | sort); do
        local base="${m%.json}" bin="$WORK/in.bin"
        local expected; expected=$(jq -r '.current.hash // empty' "$m" 2>/dev/null)
        local is_neg=0; [ -s "${base}.expect" ] && is_neg=1   # EEST expect_exception

        if ! "$INPUTGEN" --manifest "$m" --output "$bin" >/dev/null 2>&1; then
            echo "FAIL(inputgen) $FIX $m" >> "$LOG"   # the guest never ran
            continue
        fi

        local actual guest_rc fatal
        # A guest fatal is an abort(). RLIMIT_CORE = 1 byte makes the kernel
        # skip a piped core_pattern (apport), which costs ~8 s per abort.
        actual=$(timeout 60 prlimit --core=1 "$GUEST" "$bin" 2>"$bin.err" | tail -1)
        guest_rc=${PIPESTATUS[0]}
        fatal=$(grep -m1 '^guest: ' "$bin.err")   # the guest's own rejection

        # A fork the guest doesn't implement yet rejects every block, valid
        # or not: that is no evidence the guest caught an invalid one.
        if [[ "$fatal" == *"unknown fork_id"* ]]; then
            echo "FAIL(unsupported_fork) $FIX $m" >> "$LOG"
        elif [ $is_neg -eq 1 ]; then
            # A fatal rejects it; a wrong hash only counts for block-level
            # exceptions (on a tx-level one the hash commits to the bad tx).
            local tx_level=0
            tr '|' '\n' < "${base}.expect" | grep -qv '^TransactionException\.' || tx_level=1
            if [ -n "$fatal" ] || { [ $guest_rc -eq 0 ] && [ $tx_level -eq 0 ] && [ "$actual" != "$expected" ]; }; then
                echo "PASS_NEG(guest) $FIX $m" >> "$LOG"
            elif [ $guest_rc -ne 0 ]; then
                echo "FAIL(guest_crash) $FIX $m" >> "$LOG"
            elif ! tr '|' '\n' < "${base}.expect" \
                    | grep -qvxE 'BlockException\.RLP_(STRUCTURES_ENCODING|WITHDRAWALS_NOT_READ)'; then
                echo "NA_NEG(rlp_envelope) $FIX $m" >> "$LOG"
            else
                echo "FAIL_NEG(guest_accepted_bad_block) $FIX $m" >> "$LOG"
            fi
        elif [ -n "$expected" ] && [ "$actual" = "$expected" ]; then
            echo "PASS $FIX $m" >> "$LOG"
        else
            echo "FAIL $FIX $m actual=$actual expected=$expected ${fatal:+fatal=\"$fatal\"}" >> "$LOG"
        fi
    done
    rm -rf "$WORK"

    # Blocks that got no result (unsupported network, a block reth can't
    # decode, bridge failure) — counted, so nothing is dropped silently.
    touch "$LOG"
    local want got
    want=$(jq '[.[].blocks | length] | add // 0' "$FIX")
    got=$(grep -vc '^BRIDGE_FAIL' "$LOG")
    if [ "$got" -lt "$want" ]; then
        echo "MISSING $((want - got)) $FIX" >> "$LOG"
    fi
}
export -f run_fixture
export BRIDGE INPUTGEN GUEST OUT

find "$@" -name "*.json" | sort | xargs -P "$JOBS" -I {} bash -c 'run_fixture "$1"' _ {}

LOG="$OUT/results.log"
cat "$OUT"/results/*.log > "$LOG" 2>/dev/null
rm -rf "$OUT/results" "$OUT/work"

echo "== $(find "$@" -name '*.json' | wc -l) fixtures, guest $GUEST"
awk '{print $1}' "$LOG" | sort | uniq -c
awk '$1=="MISSING"{s+=$2} END{print s+0, "blocks MISSING"}' "$LOG"
# Per fixture directory: PASS / FAIL-ish / MISSING blocks.
echo "== per directory (pass/total)"
awk '{
    if ($1 == "MISSING") { n = $2; f = $3 } else { n = 1; f = $2 }
    sub(/\/[^\/]*$/, "", f); tot[f] += n
    if ($1 == "PASS" || $1 ~ /^PASS_NEG/ || $1 ~ /^NA_NEG/) ok[f] += n
} END { for (d in tot) printf "%6d/%-6d %s\n", ok[d], tot[d], d }' "$LOG" | sort -k2
echo "results: $LOG"

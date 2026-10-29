#!/bin/bash
# Prover-killer sweep: run EEST benchmark fixtures (the zkevm-benchmark
# worst-case blocks, e.g. 200M gas) through the real ZisK ELF in ziskemu and
# check every output.
#
#   scripts/killer_sweep.sh [-g HOST] [-e ELF] [-z ZISKEMU] [-o OUT] [-j JOBS] PATH...
#
# Phase 1 (per fixture, parallel): eest-witness-gen → input-gen-from-manifest
#   → host guest (block hash + public output). HOST and ELF must be built with
#   -DZEG_FORK_FROM_INPUT=ON (`make guest-test elf-test`).
# Phase 2 (per block, biggest input first): ziskemu on the ELF.
#
# PASS = the ELF's 32-byte output equals the host's public output (the
# EIP-8025 new_payload_request_root) and the host's block hash equals the
# fixture's. Otherwise: EMU_DIFF (ELF != host), HASH_MISMATCH (both agree but
# the hash is wrong), EMU_ERR, EMU_TIMEOUT, IG_FAIL; NEG_ prefix on
# expect_exception blocks. Writes OUT/results.log (verdict rc steps secs
# fixture block) and prints a tally plus the 20 costliest blocks by steps.
# Env: MAXSTEPS (default 2^36-1), TMO (per-block seconds, default 7200),
# P1_JOBS (phase-1 jobs, default nproc/2), SKIP_P1=1 (rerun phase 2 only).
set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
HOST="$REPO/cpp-guest/build-test-evmone/zisk_eth_guest"
ELF="$REPO/cpp-guest/zisk/build-test-evmone/zisk_eth_guest.elf"
ZISKEMU=$(command -v ziskemu || echo "$HOME/.zisk/bin/ziskemu")
OUT="$REPO/build/killer"
JOBS=4
while getopts "g:e:z:o:j:" opt; do
    case $opt in
        g) HOST=$(realpath "$OPTARG") ;;
        e) ELF=$(realpath "$OPTARG") ;;
        z) ZISKEMU=$(realpath "$OPTARG") ;;
        o) OUT=$(realpath -m "$OPTARG") ;;
        j) JOBS=$OPTARG ;;
        *) exit 2 ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || { sed -n 2,20p "$0"; exit 2; }

BRIDGE="$REPO/eest-witness-gen/target/release/eest-witness-gen"
INPUTGEN="$REPO/target/release/input-gen-from-manifest"
for b in "$BRIDGE" "$INPUTGEN" "$HOST" "$ZISKEMU"; do
    [ -x "$b" ] || { echo "missing binary: $b" >&2; exit 1; }
done
[ -f "$ELF" ] || { echo "missing ELF: $ELF" >&2; exit 1; }

MAXSTEPS=${MAXSTEPS:-68719476735}
TMO=${TMO:-7200}
P1_JOBS=${P1_JOBS:-$(( ($(nproc) + 1) / 2 ))}
mkdir -p "$OUT/work" "$OUT/p1"
export BRIDGE INPUTGEN HOST ELF ZISKEMU OUT MAXSTEPS TMO

# One fixture: one line per block in OUT/p1/<id>:
#   status neg expected_hash host_hash host_output input_base fixture name
phase1() {
    local FIX=$1 ID W P
    ID=$(echo "$FIX" | md5sum | cut -c1-12); W=$OUT/work/$ID
    [ -e "$OUT/p1/$ID" ] && return 0     # done in an earlier run
    P=$OUT/p1/.$ID.tmp; rm -f "$P"
    rm -rf "$W"; mkdir -p "$W"
    "$BRIDGE" --fixture "$FIX" --output-dir "$W" >"$W/bridge.log" 2>&1 || echo "BRIDGE_FAIL $FIX" >>"$P"
    local i=0 m
    for m in $(find "$W" -name 'block-*.json' | sort); do
        i=$((i+1))
        local base=${m%.json} B=$W/b$i exp neg=0 name
        exp=$(jq -r '.current.hash // empty' "$m")
        [ -s "$base.expect" ] && neg=1
        name=$(basename "$(dirname "$m")")/$(basename "$m" .json)
        if ! "$INPUTGEN" --manifest "$m" --output "$B.bin" >"$B.ig.log" 2>&1; then
            echo "IG_FAIL $neg $exp - - $B $FIX $name" >>"$P"; continue
        fi
        # The host guest prints the block hash, then the public output. A
        # fatal is an abort(): RLIMIT_CORE = 1 byte skips apport (~8 s each).
        local outl hh hn
        outl=$(timeout 600 prlimit --core=1 "$HOST" "$B.bin" 2>"$B.host.err" | grep '^0x')
        hh=$(echo "$outl" | head -1); hn=$(echo "$outl" | tail -1)
        [ -z "$hh" ] && { hh=-; hn=-; }
        # ziskemu input: 8-byte little-endian length, then the input.
        python3 -I -c "import struct,sys; d=open(sys.argv[1],'rb').read(); open(sys.argv[2],'wb').write(struct.pack('<Q',len(d))+d)" "$B.bin" "$B.zin"
        rm -f "$B.bin"
        echo "OK $neg $exp $hh $hn $B $FIX $name" >>"$P"
    done
    touch "$P"; mv "$P" "$OUT/p1/$ID"
}

phase2() {
    local st neg exp hh hn B FIX name
    read -r st neg exp hh hn B FIX name <<<"$1"
    [ "$st" = OK ] || { echo "IG_FAIL rc=- steps=- secs=0 $FIX $name"; return; }
    local sz mem=() t0 t1 rc steps eo=-
    sz=$(stat -c%s "$B.zin")
    # ziskemu's default input cap is 128 MiB; the ELF's input region is 2 GiB.
    [ "$sz" -gt 100000000 ] && mem=(--max-input-mem 2147483648)
    t0=$(date +%s.%N)
    timeout "$TMO" "$ZISKEMU" -e "$ELF" -i "$B.zin" -o "$B.out" -m -n "$MAXSTEPS" "${mem[@]}" >"$B.emu.log" 2>&1
    rc=$?; t1=$(date +%s.%N)
    steps=$(grep -o 'steps=[0-9]*' "$B.emu.log" | tail -1 | cut -d= -f2)
    [ -s "$B.out" ] && eo=0x$(head -c32 "$B.out" | xxd -p -c32)
    rm -f "$B.out"
    local verdict
    if [ $rc -eq 124 ]; then verdict=EMU_TIMEOUT
    elif [ $rc -ne 0 ]; then verdict=EMU_ERR
    elif [ "$eo" != "$hn" ] || [ "$hn" = - ]; then verdict=EMU_DIFF
    elif [ "$hh" = "$exp" ]; then verdict=PASS
    else verdict=HASH_MISMATCH          # ELF == host, both differ from the fixture
    fi
    [ "$neg" = 1 ] && verdict="NEG_$verdict"
    printf '%s rc=%s steps=%s secs=%.1f %s %s\n' "$verdict" "$rc" "${steps:--}" \
        "$(echo "$t1 - $t0" | bc)" "$FIX" "$name"
}
export -f phase1 phase2

if [ "${SKIP_P1:-0}" != 1 ]; then
    find "$@" -name '*.json' -not -path '*/.meta/*' | sort \
        | xargs -P "$P1_JOBS" -I{} bash -c 'phase1 "$1"' _ {}
fi
cat "$OUT"/p1/[!.]* > "$OUT/blocks.txt"
grep -h '^BRIDGE_FAIL' "$OUT/blocks.txt" > "$OUT/bridge_fail.txt"
grep -v '^BRIDGE_FAIL' "$OUT/blocks.txt" > "$OUT/blocks.run"
echo "phase 1: $(wc -l <"$OUT/blocks.run") blocks, $(wc -l <"$OUT/bridge_fail.txt") bridge failures"

# Biggest inputs first, so the slowest blocks don't finish last.
while read -r l; do
    set -- $l
    echo "$(stat -c%s "$6.zin" 2>/dev/null || echo 0) $l"
done <"$OUT/blocks.run" | sort -rn | cut -d' ' -f2- | tr '\n' '\0' \
    | xargs -0 -P "$JOBS" -I{} bash -c 'phase2 "$1"' _ {} > "$OUT/results.log"

echo "== $(wc -l <"$OUT/results.log") blocks, ELF $ELF"
awk '{print $1}' "$OUT/results.log" | sort | uniq -c
echo "== costliest 20 by steps"
awk '{s=$3; sub(/steps=/, "", s); if (s != "-") print s, $1, $6}' "$OUT/results.log" \
    | sort -rn | head -20 | awk '{printf "%14d %-6s %s\n", $1, $2, $3}'
echo "results: $OUT/results.log"

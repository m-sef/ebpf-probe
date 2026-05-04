#!/usr/bin/env bash
# Compare eBPF probe counters against perf stat over a timed window.
#
# Core events: sums /sys/fs/bpf/ebpf_probe/core/* (one file per CPU) and
# compares the delta against `perf stat -a` for the same hardware events.
#
# RAPL:        reads /sys/fs/bpf/ebpf_probe/rapl/pkg (raw u64 counter),
# multiplies by 2^-32 for Joules, and compares against perf/energy-pkg.
#
# Usage: sudo ./scripts/validate-with-perf.sh [duration_seconds]
#        default duration: 5

#------------------------------------------------------------------------------
# LET IT BE KNOWN, THIS SCRIPT WAS WRITTEN ENTIRELY BY CLAUDE
#------------------------------------------------------------------------------

set -euo pipefail

DURATION=${1:-5}
# Intel RAPL: 1 count = 2^-32 Joules
RAPL_SCALE="2.3283064365386962890625e-10"
BPF_CORE_DIR="/sys/fs/bpf/ebpf_probe/core"
BPF_RAPL_PKG="/sys/fs/bpf/ebpf_probe/rapl/pkg"

[[ $EUID -eq 0 ]] || { echo "ERROR: must be run as root" >&2; exit 1; }

for path in "$BPF_CORE_DIR" "$BPF_RAPL_PKG"; do
    [[ -e "$path" ]] || {
        echo "ERROR: $path not found — is ebpf_probe running?" >&2
        exit 1
    }
done

# Read all per-core iterator files and return space-separated sums:
#   rx_bytes instructions cpu_cycles ref_cpu_cycles cache_misses
# Each file emits one CSV line: rx_bytes,instructions,cpu_cycles,ref_cpu_cycles,cache_misses
read_core_totals() {
    local rx=0 ins=0 cyc=0 ref=0 cm=0
    for f in "$BPF_CORE_DIR"/*; do
        IFS=',' read -r _rx _ins _cyc _ref _cm < "$f"
        (( rx  += _rx  )) || true
        (( ins += _ins )) || true
        (( cyc += _cyc )) || true
        (( ref += _ref )) || true
        (( cm  += _cm  )) || true
    done
    printf '%d %d %d %d %d\n' "$rx" "$ins" "$cyc" "$ref" "$cm"
}

# Print ratio a/b, or N/A if b is zero
ratio() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        if (b + 0 == 0) { print "N/A"; exit }
        printf "%.4f\n", a / b
    }'
}

echo "=== eBPF probe vs perf stat (${DURATION}s window, system-wide) ==="
echo

# --- Before snapshot ---
read -r bpf_rx0 bpf_ins0 bpf_cyc0 bpf_ref0 bpf_cm0 <<< "$(read_core_totals)"
bpf_rapl0=$(< "$BPF_RAPL_PKG")

# --- System-wide perf stat for DURATION seconds ---
# 2>&1 because perf stat writes to stderr
perf_raw=$(perf stat -a \
    -e instructions \
    -e cpu-cycles \
    -e ref-cycles \
    -e cache-misses \
    -e power/energy-pkg/ \
    -- sleep "$DURATION" 2>&1)

# --- After snapshot ---
read -r bpf_rx1 bpf_ins1 bpf_cyc1 bpf_ref1 bpf_cm1 <<< "$(read_core_totals)"
bpf_rapl1=$(< "$BPF_RAPL_PKG")

# --- BPF deltas ---
d_ins=$(( bpf_ins1 - bpf_ins0 ))
d_cyc=$(( bpf_cyc1 - bpf_cyc0 ))
d_ref=$(( bpf_ref1 - bpf_ref0 ))
d_cm=$(( bpf_cm1  - bpf_cm0  ))
d_rapl=$(( bpf_rapl1 - bpf_rapl0 ))
bpf_joules=$(awk -v raw="$d_rapl" -v scale="$RAPL_SCALE" \
    'BEGIN { printf "%.4f", raw * scale }')

# --- Parse perf stat output ---
# Lines look like: "     12,345,678      instructions   # ..."
perf_ins=$(    awk '/instructions/{  gsub(/,/,"",$1); print $1+0; exit}' <<< "$perf_raw")
perf_cyc=$(    awk '/cpu-cycles/{    gsub(/,/,"",$1); print $1+0; exit}' <<< "$perf_raw")
perf_ref=$(    awk '/ref-cycles/{    gsub(/,/,"",$1); print $1+0; exit}' <<< "$perf_raw")
perf_cm=$(     awk '/cache-misses/{  gsub(/,/,"",$1); print $1+0; exit}' <<< "$perf_raw")
# RAPL line: "   12.34 Joules  power/energy-pkg/"  or  "   12.34  power/energy-pkg/"
perf_joules=$( awk '/power\/energy-pkg\//{           print $1+0; exit}' <<< "$perf_raw")

# --- Report ---
FMT='%-16s  %22s  %22s  %12s\n'
printf "$FMT" "Metric" "eBPF delta" "perf stat" "ratio (ebpf/perf)"
printf "$FMT" "------" "----------" "---------" "-----------------"
printf "$FMT" "instructions"  "$d_ins"       "${perf_ins:-N/A}"    "$(ratio "$d_ins"      "${perf_ins:-0}")"
printf "$FMT" "cpu-cycles"    "$d_cyc"       "${perf_cyc:-N/A}"    "$(ratio "$d_cyc"      "${perf_cyc:-0}")"
printf "$FMT" "ref-cycles"    "$d_ref"       "${perf_ref:-N/A}"    "$(ratio "$d_ref"      "${perf_ref:-0}")"
printf "$FMT" "cache-misses"  "$d_cm"        "${perf_cm:-N/A}"     "$(ratio "$d_cm"       "${perf_cm:-0}")"
echo
printf "$FMT" "Metric" "eBPF (Joules)" "perf stat (Joules)" "ratio (ebpf/perf)"
printf "$FMT" "------" "-------------" "------------------" "-----------------"
printf "$FMT" "energy-pkg"   "$bpf_joules"  "${perf_joules:-N/A}" "$(ratio "$bpf_joules" "${perf_joules:-0}")"

echo
echo "--- raw perf stat output ---"
echo "$perf_raw"

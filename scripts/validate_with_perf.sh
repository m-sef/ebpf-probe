#!/usr/bin/env bash
# Validate eBPF probe hardware counters against perf stat over a timed window.
#
# Takes a snapshot of /sys/fs/bpf/ebpf_probe/core/* before and after a
# `perf stat -a` run, computes per-event deltas, and normalizes them for
# PMU time-multiplexing using the enabled/running fields from each
# bpf_perf_event_value:
#
#   normalized = raw_delta * (enabled_delta / running_delta)
#
# where the deltas are over the measurement window, per CPU, summed across
# all CPUs. The mux% column shows how much of the enabled time the counter
# was actually running (100% = no multiplexing, lower = scaling applied).
#
# RAPL: reads /sys/fs/bpf/ebpf_probe/rapl/pkg (CSV: counter,unit,scale) and
# converts to Joules using the scale field emitted by the rapl_iterator.
#
# Usage: sudo ./scripts/validate_with_perf.sh [duration_seconds]
#        default duration: 5

set -euo pipefail

DURATION=${1:-5}
BPF_CORE_DIR="/sys/fs/bpf/ebpf_probe/core"
BPF_RAPL_PKG="/sys/fs/bpf/ebpf_probe/rapl/pkg"
EVENTS=(instructions cpu_cycles ref_cpu_cycles cache_misses)

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

[[ $EUID -eq 0 ]] || { echo "ERROR: must be run as root" >&2; exit 1; }
for _path in "$BPF_CORE_DIR" "$BPF_RAPL_PKG"; do
    [[ -e "$_path" ]] || { echo "ERROR: $_path not found — is ebpf_probe running?" >&2; exit 1; }
done
command -v perf >/dev/null || { echo "ERROR: perf not found in PATH" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

# Read all per-CPU core iterator files and accumulate into an associative
# array passed by nameref. Each file emits CSV lines:
#
#   #core,event,counter,enabled,running
#   N,rx_packets,COUNT,N/A,N/A
#   N,rx_bytes,COUNT,N/A,N/A
#   N,instructions,COUNT,ENABLED_NS,RUNNING_NS
#   ...
#
# Keys written: rx_bytes, <event>_counter, <event>_enabled, <event>_running
read_snapshot() {
    local -n _out=$1
    while IFS=, read -r core event counter enabled running; do
        [[ "$core" == "#core" ]] && continue
        case "$event" in
            rx_packets) continue ;;
            rx_bytes)
                (( _out[rx_bytes] += counter )) || true
                ;;
            instructions|cpu_cycles|ref_cpu_cycles|cache_misses)
                (( _out[${event}_counter] += counter )) || true
                (( _out[${event}_enabled] += enabled )) || true
                (( _out[${event}_running] += running )) || true
                ;;
        esac
    done < <(cat "$BPF_CORE_DIR"/*)
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Scale a raw counter for PMU time-multiplexing.
# counter * (enabled / running), or counter if running == 0.
normalize() {
    awk -v c="$1" -v e="$2" -v r="$3" \
        'BEGIN { printf "%.0f\n", (r > 0 && e > 0) ? c * (e / r) : c }'
}

# Percentage of enabled time that the counter was actually running.
mux_pct() {
    awk -v r="$1" -v e="$2" \
        'BEGIN { if (e > 0) printf "%.1f%%\n", 100.0 * r / e; else print "100.0%" }'
}

ratio() {
    awk -v a="$1" -v b="$2" \
        'BEGIN { if (b + 0 == 0) { print "N/A"; exit } printf "%.4f\n", a / b }'
}

# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

declare -A snap0 snap1

for e in "${EVENTS[@]}"; do
    snap0[${e}_counter]=0; snap0[${e}_enabled]=0; snap0[${e}_running]=0
    snap1[${e}_counter]=0; snap1[${e}_enabled]=0; snap1[${e}_running]=0
done
snap0[rx_bytes]=0; snap1[rx_bytes]=0

echo "=== eBPF probe vs perf stat (${DURATION}s window, system-wide) ==="
echo

# Read the rapl_iterator CSV: "#counter,unit,scale\n<counter>,<unit>,<scale>"
# Sets caller variables: <prefix>_counter, rapl_unit, rapl_scale (from first call).
read_rapl_snapshot() {
    local prefix=$1
    while IFS=, read -r _c _u _s; do
        [[ "$_c" == "#counter" ]] && continue
        printf -v "${prefix}_counter" '%s' "$_c"
        rapl_unit="$_u"
        rapl_scale="$_s"
        return
    done < "$BPF_RAPL_PKG"
}

# t0 snapshot
read_snapshot snap0
read_rapl_snapshot rapl0

# perf stat writes to stderr; capture both streams
perf_raw=$(perf stat -a \
    -e instructions \
    -e cpu-cycles \
    -e ref-cycles \
    -e cache-misses \
    -e power/energy-pkg/ \
    -- sleep "$DURATION" 2>&1)

# t1 snapshot
read_snapshot snap1
read_rapl_snapshot rapl1

# ---------------------------------------------------------------------------
# Deltas and normalization
# ---------------------------------------------------------------------------

declare -A d_norm d_mux

for e in "${EVENTS[@]}"; do
    dc=$(( snap1[${e}_counter] - snap0[${e}_counter] ))
    de=$(( snap1[${e}_enabled] - snap0[${e}_enabled] ))
    dr=$(( snap1[${e}_running] - snap0[${e}_running] ))
    d_norm[$e]=$(normalize "$dc" "$de" "$dr")
    d_mux[$e]=$(mux_pct    "$dr" "$de")
done

d_rx=$(( snap1[rx_bytes] - snap0[rx_bytes] ))
d_rapl=$(( rapl1_counter - rapl0_counter ))
bpf_joules=$(awk -v raw="$d_rapl" -v s="$rapl_scale" 'BEGIN { printf "%.4f", raw * s }')

# ---------------------------------------------------------------------------
# Parse perf stat output
# ---------------------------------------------------------------------------

# perf stat lines look like:  "   12,345,678,901      instructions   # ..."
perf_ins=$(    awk '/[^-]instructions/{  gsub(/,/,"",$1); print $1+0; exit}' <<< "$perf_raw")
perf_cyc=$(    awk '/cpu-cycles/{        gsub(/,/,"",$1); print $1+0; exit}' <<< "$perf_raw")
perf_ref=$(    awk '/ref-cycles/{        gsub(/,/,"",$1); print $1+0; exit}' <<< "$perf_raw")
perf_cm=$(     awk '/cache-misses/{      gsub(/,/,"",$1); print $1+0; exit}' <<< "$perf_raw")
# RAPL line: "   12.34 Joules   power/energy-pkg/"  (or without "Joules" on older perf)
perf_joules=$( awk '/power\/energy-pkg\//{            print $1+0; exit}' <<< "$perf_raw")

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

FMT='%-16s  %24s  %22s  %8s  %10s\n'

printf "$FMT" "Event" "eBPF (normalized)" "perf stat" "mux%" "ratio"
printf "$FMT" "-----" "-----------------" "---------" "----" "-----"
printf "$FMT" "instructions"  "${d_norm[instructions]}"   "${perf_ins:-N/A}"    "${d_mux[instructions]}"   "$(ratio "${d_norm[instructions]}"   "${perf_ins:-0}")"
printf "$FMT" "cpu-cycles"    "${d_norm[cpu_cycles]}"     "${perf_cyc:-N/A}"    "${d_mux[cpu_cycles]}"     "$(ratio "${d_norm[cpu_cycles]}"     "${perf_cyc:-0}")"
printf "$FMT" "ref-cycles"    "${d_norm[ref_cpu_cycles]}" "${perf_ref:-N/A}"    "${d_mux[ref_cpu_cycles]}" "$(ratio "${d_norm[ref_cpu_cycles]}" "${perf_ref:-0}")"
printf "$FMT" "cache-misses"  "${d_norm[cache_misses]}"   "${perf_cm:-N/A}"     "${d_mux[cache_misses]}"   "$(ratio "${d_norm[cache_misses]}"   "${perf_cm:-0}")"

echo
printf "%-16s  %24s  %22s  %10s\n" "Event" "eBPF" "perf stat" "ratio"
printf "%-16s  %24s  %22s  %10s\n" "-----" "----" "---------" "-----"
printf "%-16s  %24s  %22s  %10s\n" \
    "energy-pkg (${rapl_unit})" "$bpf_joules" "${perf_joules:-N/A}" "$(ratio "$bpf_joules" "${perf_joules:-0}")"

echo
printf "%-16s  %d bytes\n" "rx_bytes" "$d_rx"

echo
echo "--- raw perf stat output ---"
echo "$perf_raw"

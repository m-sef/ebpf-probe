#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
LOG_FOLDER_PATH=/tmp/ebpf-probe
DURATION=$1
FREQUENCY=$2

mkdir -p "$LOG_FOLDER_PATH"

(
    > "$LOG_FOLDER_PATH/rapl.log"
    END=$(( $(date +%s) + DURATION ))
    while [ "$(date +%s)" -lt "$END" ]; do
        sudo bash -c 'cat /sys/fs/bpf/ebpf_probe/rapl/*' >> "$LOG_FOLDER_PATH/rapl.log" 2>/dev/null
        sleep $(( 1 / $FREQUENCY ))
    done
) &
PID=$!

echo "$PID"

exit 0
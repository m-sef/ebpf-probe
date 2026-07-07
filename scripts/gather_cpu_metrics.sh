#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
LOG_FOLDER_PATH=/tmp/ebpf-probe
DURATION=$1

mkdir -p "$LOG_FOLDER_PATH"

(
    END=$(( $(date +%s) + DURATION ))
    while [ "$(date +%s)" -lt "$END" ]; do
        sudo bash -c 'cat /sys/fs/bpf/ebpf_probe/cpu*/summary' | column -t -s, >> "$LOG_FOLDER_PATH/cpu.log" 2>/dev/null
        sleep 1
    done
) &
PID=$!

echo "$PID"

exit 0
#!/usr/bin/env bash
# Usage: read_rapl LOG_FILE_PATH FREQUENCY
# Brief: Intended to be piped/redirected to file

LOG_FILE_PATH=$1
FREQUENCY=$2

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 LOG_FILE_PATH FREQUENCY"
    exit 1
fi

while true
do
    cat /sys/fs/bpf/ebpf_probe/rapl/* >> $LOG_FILE_PATH
    sleep $FREQUENCY
done

exit 0
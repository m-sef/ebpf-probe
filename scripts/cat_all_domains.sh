#!/usr/bin/env bash

cat /sys/fs/bpf/ebpf_probe/rapl/* | column -t -s,

exit 0
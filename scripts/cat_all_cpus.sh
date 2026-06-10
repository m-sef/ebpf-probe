#!/usr/bin/env bash

cat /sys/fs/bpf/ebpf_probe/cpu*/summary | column -t -s,

exit 0
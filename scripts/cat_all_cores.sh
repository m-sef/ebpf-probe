#!/usr/bin/env bash
cat /sys/fs/bpf/ebpf_probe/core/* | column -t -s,
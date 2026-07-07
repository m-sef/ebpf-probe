#!/usr/bin/env bash

sudo bash -c 'cat /sys/fs/bpf/ebpf_probe/cpu*/summary' | column -t -s,

exit 0
#!/usr/bin/env bash

for ((i = 0; i < $(nproc); i++)); do
    cat "/sys/fs/bpf/ebpf_probe/core/$i"
done
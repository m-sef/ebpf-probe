#!/usr/bin/env python3
from pathlib import Path

EBPF_PROBE_DIR = "/sys/fs/bpf/ebpf_probe/"

def main() -> None:
    for subpath in Path(EBPF_PROBE_DIR).iterdir():
        print(subpath)

if __name__ == '__main__':
    main()
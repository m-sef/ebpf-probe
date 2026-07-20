#!/usr/bin/env python3
from pathlib import Path
import argparse
import gc
import sys
import time

EBPF_PROBE_DIR = "/sys/fs/bpf/ebpf_probe/"
LOG_DIR        = "/tmp/ebpf_probe/"

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--interval", type=float, default=1000.0, help="sample interval (milliseconds)")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    interval_s = args.interval / 1000.0

    iterator_paths = []

    for subpath in Path(EBPF_PROBE_DIR).iterdir():
        if "rapl" in subpath.name:
            continue

        iterator_paths.append(subpath / "summary")

    # GC pauses are a major source of jitter at ms-scale sampling rates.
    gc.disable()

    out = sys.stdout
    next_tick = time.perf_counter()

    try:
        while True:
            timestamp_ns = time.time_ns()
            lines = []

            for path in iterator_paths:
                with open(path, mode='r') as file:
                    for line in file:
                        lines.append(f"{timestamp_ns},{line.rstrip()}")

            if lines:
                out.write("\n".join(lines) + "\n")
                out.flush()

            next_tick += interval_s
            sleep_s = next_tick - time.perf_counter()
            if sleep_s > 0:
                time.sleep(sleep_s)
            else:
                # Fell behind: drop the missed tick(s) instead of busy-looping.
                next_tick = time.perf_counter()
    except:
        print("")

if __name__ == '__main__':
    main()
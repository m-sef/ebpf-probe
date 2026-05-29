#!/usr/bin/env python3
# Usage: log_cores.py [-h] -d DURATION -e EVENT -f FREQUENCY

import os
import argparse
import time
import socket
from datetime import datetime
import pandas

COLUMNS = ['core', 'event', 'counter', 'enabled', 'running']
EVENTS  = ['rx_packets', 'rx_bytes', 'instructions', 'cpu_cycles', 'ref_cpu_cycles', 'cache_misses']

def sample_core(cpu_idx : int) -> pandas.DataFrame:
    data_frame = pandas.read_csv(f"/sys/fs/bpf/ebpf_probe/core/{cpu_idx}",
        comment='#', header=None, names=COLUMNS, na_values='N/A')
    data_frame['timestamp'] = time.time()
    return data_frame

def sample_all_cores() -> pandas.DataFrame:
    data_frames = []

    for cpu_idx in range(os.cpu_count()):
        data_frames.append(sample_core(cpu_idx))

    combined = pandas.concat(data_frames)
    timestamp = combined['timestamp'].iloc[0]

    summed = combined.groupby('event')[['counter', 'enabled', 'running']].sum().reset_index()
    summed['timestamp'] = timestamp

    return summed

def process_sample(sample_df: pandas.DataFrame, start_time: float) -> pandas.DataFrame:
    scales = (sample_df["enabled"] / sample_df["running"]).fillna(1.0)
    sample_df = sample_df.copy()
    sample_df['normalized_counter'] = sample_df['counter'] * scales

    row = sample_df.pivot_table(columns='event', values='normalized_counter', aggfunc='first')
    row.index = [sample_df['timestamp'].iloc[0] - start_time]
    row.index.name = 'timestamp'
    return row

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d', '--duration', type=float, default=10.0, required=True, help="Duration to sample for in seconds")
    parser.add_argument(
        '-f', '--frequency', type=float, default=1.0, required=True, help="Frequency to sample in seconds")
    args = parser.parse_args()

    duration  : float = args.duration
    frequency : float = args.frequency
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    hostname = socket.gethostname().split('.')[0]
    csv_path = f"{hostname}-ebpf-{timestamp}.log"

    start_time = None
    write_header = True

    try:
        end_time = time.time() + duration
        while (time.time() < end_time):
            start = time.time()

            sample = sample_all_cores()

            if start_time is None:
                start_time = sample['timestamp'].iloc[0]

            row = process_sample(sample, start_time)
            row.to_csv(csv_path, mode='a', header=write_header)
            write_header = False

            elapsed = time.time() - start
            time.sleep(max(0, frequency - elapsed))
    except KeyboardInterrupt:
        pass

    print(pandas.read_csv(csv_path, index_col='timestamp'))

if __name__ == '__main__':
    main()

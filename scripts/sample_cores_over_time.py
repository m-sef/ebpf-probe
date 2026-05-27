#!/usr/bin/env python3
# Usage: sample_cores_over_time.py [-h] -d DURATION -e EVENT -f FREQUENCY

import os
import sys
import argparse
import time
import matplotlib.pyplot
import pandas

COLUMNS = ['core', 'event', 'counter', 'enabled', 'running']

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

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d', '--duration', type=float, default=10.0, required=True, help="Duration to sample for in seconds")
    parser.add_argument(
        '-e', '--event', type=str, required=True, help="Event to graph")
    parser.add_argument(
        '-f', '--frequency', type=float, default=1.0, required=True, help="Frequency to sample in seconds")
    #parser.add_argument(
    #    '-g', '--graph', type=bool, default=False, required=False, help="Show matplotlib graph via GUI")
    args = parser.parse_args()

    duration  : float = args.duration
    frequency : float = args.frequency

    data_frames = []

    end_time = time.time() + duration
    while (time.time() < end_time):
        start = time.time()

        data_frames.append(sample_all_cores())

        elapsed = time.time() - start
        time.sleep(max(0, frequency - elapsed))
    
    data_frame = pandas.concat(data_frames)
    scales = (data_frame["enabled"] / data_frame["running"]).fillna(1.0)
    data_frame['normalized_counter'] = data_frame['counter'] * scales
    
    # Pivot the table
    data_frame = data_frame.pivot_table(index='timestamp', columns='event', values='normalized_counter', aggfunc='first')

    # Normalize the index
    data_frame.index = data_frame.index - data_frame.index.min()

    print(data_frame)

    if (args.graph):
        axis = data_frame[args.event].diff().plot()
        axis.set_xlabel("Time (s)")
        axis.set_ylabel(args.event)
        matplotlib.pyplot.ticklabel_format(style='plain', axis='y')
        matplotlib.pyplot.show()

if __name__ == '__main__':
    main()
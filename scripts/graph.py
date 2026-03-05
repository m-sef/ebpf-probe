#!/usr/bin/env python3
import sys
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd

def main() -> None:
    file_path : str = "build/test.log"

    data_frame = pd.read_csv(file_path, comment='#')
    data_frame = data_frame.groupby('timestamp')[['total_packets_recieved', 'total_bytes_recieved']].sum().reset_index()

    plt.plot(
        pd.to_datetime(data_frame['timestamp'], format="%Y-%m-%d %H-%M-%S"),
        data_frame['total_packets_recieved'])

    plt.title(file_path)
    plt.xlabel("Time")
    plt.ylabel("Throughput (Bps)")

    plt.ticklabel_format(
        useOffset=False,
        style='plain',
        axis='y')

    plt.grid()

    plt.show()

if __name__ == '__main__':
    main()

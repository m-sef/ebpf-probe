#!/usr/bin/env python3
import sys
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd

def main() -> None:
    file_path : str = "build/test.csv"

    data_frame = pd.read_csv(file_path, comment='#')

    data_frame['datetime'] = pd.to_datetime(data_frame['time'], unit='ns')
    data_frame = data_frame.set_index('datetime')

    data_frame = data_frame[['size']].resample('1s').sum()
    data_frame['size'] = data_frame['size'] / 1024

    plt.plot(
        data_frame.index,
        data_frame['size'],
        linewidth=1.0)

    plt.title(file_path)
    plt.xlabel("Time")
    plt.ylabel("Throughput (Kilobytes/sec)")

    plt.ticklabel_format(
        useOffset=False,
        style='plain',
        axis='y')

    plt.grid(
        True,
        linestyle='--',
        alpha=0.5)

    plt.show()

if __name__ == '__main__':
    main()

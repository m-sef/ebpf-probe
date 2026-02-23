#!/usr/bin/env python3
# usage: graph <log file path>
import sys
from datetime import datetime
import matplotlib.pyplot as plt
import csv

def main() -> None:
    file_paths : list[str] = [
        "R1000.log",
        "R3000.log",
        "R6000.log",
        "R12000.log",
        "R24000.log",
        "R100000.log"
    ]

    figures, axes = plt.subplots(nrows=3, ncols=2, sharey=True)
    
    axes = axes.flatten()

    for axis, file_path in zip(axes, file_paths):
        print("Graphing ", file_path)

        with open(file_path, 'r') as file:
            reader = csv.reader(file, delimiter=',')

            x = []
            y = []

            for row in reader:
                x.append(datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S"))
                y.append(int(row[2]))

            axis.plot(x, y)

            axis.set_title(file_path)
            axis.set_xlabel("Time")
            axis.set_ylabel("Bytes Recieved")

            axis.ticklabel_format(
                useOffset=False,
                style='plain',
                axis='y')
        
            axis.grid()

    plt.tight_layout()
    plt.show()

if __name__ == '__main__':
    main()

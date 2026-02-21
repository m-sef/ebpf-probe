#!/usr/bin/env python3
# usage: graph <log file path>
import sys
import matplotlib.pyplot as plt
import csv

def main() -> None:
    log_file_path = sys.argv[1]
    x = []
    y = []

    with open(log_file_path, 'r') as file:
        reader = csv.reader(file, delimiter=',')

        for row in reader:
            x.append(row[0])
            y.append(row[2])

    plt.plot(x, y)
    plt.show()

if __name__ == '__main__':
    main()

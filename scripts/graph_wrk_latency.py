#!/usr/bin/env python3
import matplotlib.pyplot
import pandas
import glob

def main() -> None:
    pass

if __name__ == '__main__':
    directories : list[str] = [
        "logs/2026-04-05_16:16:06"
    ]

    # Graph average latency, per thread, per second
    for directory in directories:
        data_frames : list[pandas.DataFrame] = []

        for file_path in glob.glob(f"{directory}/*-requests.txt"):
            data_frame : pandas.DataFrame = pandas.read_csv(file_path, comment='#', header=None, na_values='na')
            data_frame.columns = ['thread_id', 'request_status', 'timestamp', 'latency']
            data_frame['timestamp'] = pandas.to_datetime(data_frame['timestamp'], unit='ns')
            data_frame.set_index('timestamp')
            data_frames.append(data_frame)
        
        summed_data_frame : pandas.DataFrame = pandas.concat(data_frames)

        print(summed_data_frame)

        summed_data_frame.plot()
    
    matplotlib.pyplot.show()
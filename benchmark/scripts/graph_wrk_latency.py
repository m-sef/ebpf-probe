#!/usr/bin/env python3
import matplotlib.pyplot
import pandas
import glob

def main() -> None:
    directories : list[str] = [
        "logs/without-ebpf-probe",
        "logs/with-ebpf-probe",
    ]

    figure, axes = matplotlib.pyplot.subplots(1, 2, sharey=True)

    # Graph average latency, per thread, per second
    for axis, directory in zip(axes, directories):
        data_frames : list[pandas.DataFrame] = []

        for file_path in glob.glob(f"{directory}/*-requests.txt"):
            data_frame : pandas.DataFrame = pandas.read_csv(file_path, comment='#', header=None, na_values='na')
            data_frame.columns = ['thread_id', 'request_status', 'timestamp', 'latency']
            data_frames.append(data_frame)
        
        combined_data_frame : pandas.DataFrame = pandas.concat(data_frames)
        combined_data_frame['timestamp'] = pandas.to_datetime(combined_data_frame['timestamp'], unit='us')
        combined_data_frame = combined_data_frame.set_index('timestamp').sort_index()
        
        mean_latency_per_second     : pandas.DataFrame = combined_data_frame['latency'].resample('1s').mean()
        mean_p99_latency_per_second : pandas.DataFrame = combined_data_frame['latency'].resample('1s').quantile(0.99)

        mean_latency_per_second.plot(ax=axis)
        mean_p99_latency_per_second.plot(ax=axis)

        axis.set_title(directory)
        axis.set_xlabel("Time (s)")
        axis.set_ylabel("Latency (ms)")
        axis.legend(["Average Latency", "Average P99 Latency"])
        axis.grid(True, linestyle='--', alpha=0.5)
    
    matplotlib.pyplot.show()

if __name__ == '__main__':
    main()
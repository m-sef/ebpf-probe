#!/usr/bin/env python3
# Usage: graph_perf_logs <file_path>
# Author: Seth Moore (slmoore@hamilton.edu)
# Brief:
#   Graph perf log files produced by power-consumption-logger
import sys
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd
import numpy as np

EXPECTED_ARGC = 2

def remove_outliers(dataframe : pd.DataFrame, factor : float = 1.5) -> pd.DataFrame:
	Q1 = dataframe.quantile(0.25)
	Q3 = dataframe.quantile(0.75)
	IQR = Q3 - Q1

	upper_limit : float = Q3 + (factor * IQR)
	lower_limit : float = Q1 - (factor * IQR)
	
	return dataframe.mask((dataframe > upper_limit) | (dataframe < lower_limit))

def main() -> None:
	if len(sys.argv) < EXPECTED_ARGC:
		print("usage: graph_perf_logs <file_path>")
		exit()
	
	file_paths : list[str] = sys.argv[1:]

	figure = plt.figure(figsize=(16, 8))

	axis1 = plt.subplot2grid((2, 6), (0, 0), colspan=2)
	axis2 = plt.subplot2grid((2, 6), (0, 2), colspan=2)
	axis3 = plt.subplot2grid((2, 6), (0, 4), colspan=2)

	axis4 = plt.subplot2grid((2, 6), (1, 0), colspan=3)
	axis5 = plt.subplot2grid((2, 6), (1, 3), colspan=3)

	axes = [axis1, axis2, axis3, axis4, axis5]

	for file_path in file_paths:
		data_frame = pd.read_csv(file_path, comment='#', header=None, na_values='na')
		data_frame.columns = ['timestamp', '2', 'value', '3', 'event', '5', '6', '7', '8']
		data_frame['timestamp'] = pd.to_datetime(data_frame['timestamp'])
		data_frame = data_frame.pivot_table(index='timestamp', columns='event', values='value', aggfunc='first')
		data_frame = remove_outliers(data_frame)

		data_frame['cache-misses']     .plot(ax=axis1, title='cache-misses')
		data_frame['instructions']     .plot(ax=axis2, title='instructions')
		data_frame['ref-cycles']       .plot(ax=axis3, title='ref-cycles')

		data_frame['power/energy-pkg/'].plot(ax=axis4, title='power/energy-pkg/')
		data_frame['power/energy-ram/'].plot(ax=axis5, title='power/energy-ram/')

	for axis in axes:
		axis.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
		axis.ticklabel_format(useOffset=False, style='plain', axis='y')
		axis.tick_params(axis='x', labelsize=8)
		axis.grid(True, linestyle='--', alpha=0.5)

	figure.suptitle(file_path)
	figure.tight_layout(rect=[0, 0, 1, 0.96])
	plt.show()

if __name__ == '__main__':
	main()
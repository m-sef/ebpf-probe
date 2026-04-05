#!/usr/bin/env python3
# Usage: graph_perf_logs <file_path>
# Author: Seth Moore (slmoore@hamilton.edu)
# Brief:
#   Graph perf log files produced by power-consumption-logger
import sys
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd

EXPECTED_ARGC = 2

def remove_outliers(dataframe : pd.DataFrame, factor : float = 1.5) -> pd.DataFrame:
	Q1 = dataframe.quantile(0.25)
	Q3 = dataframe.quantile(0.75)
	IQR = Q3 - Q1

	upper_limit : float = Q3 + (factor * IQR)
	lower_limit : float = Q1 - (factor * IQR)
	
	return dataframe.mask((dataframe > upper_limit) | (dataframe < lower_limit))

def main() -> None:
	if len(sys.argv) != EXPECTED_ARGC:
		print("usage: graph_perf_logs <file_path>")
		exit()
	
	file_path : str = sys.argv[1]

	data_frame = pd.read_csv(file_path, comment='#', header=None, na_values='na')
	data_frame.columns = ['timestamp', '2', 'value', '3', 'event', '5', '6', '7', '8']
	data_frame = data_frame.pivot_table(index='timestamp', columns='event', values='value', aggfunc='first')
	data_frame = remove_outliers(data_frame)

	figure, axes = plt.subplots(2, 3, figsize=(16, 8))
	data_frame['cache-misses']     .plot(ax=axes[0][0], title='cache-misses')
	data_frame['instructions']     .plot(ax=axes[0][1], title='instructions')
	data_frame['power/energy-pkg/'].plot(ax=axes[0][2], title='power/energy-pkg/')
	data_frame['power/energy-ram/'].plot(ax=axes[1][0], title='power/energy-ram/')
	data_frame['ref-cycles']       .plot(ax=axes[1][1], title='ref-cycles')
	axes[1, 2].set_visible(False)

	print(data_frame)

	for axis in axes.flat:
		axis.ticklabel_format(useOffset=False, style='plain', axis='y')
		axis.grid(True, linestyle='--', alpha=0.5)

	figure.suptitle(file_path)
	figure.tight_layout(rect=[0, 0, 1, 0.96])
	plt.subplots_adjust(hspace=0.35, wspace=0.3)
	plt.show()

if __name__ == '__main__':
	main()
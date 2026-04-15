#!/usr/bin/env python3
# Usage: graph_perf_logs <file_path>
# Author: Seth Moore (slmoore@hamilton.edu)
# Brief:
#   Graph perf log files produced by power-consumption-logger
import sys
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.ticker as tkr
import pandas as pd
import numpy as np

EXPECTED_ARGC = 2

def get_interquartile_range(dataframe : pd.DataFrame, factor : float = 1.5) -> tuple[float, float]:
	Q1 = dataframe.quantile(0.25)
	Q3 = dataframe.quantile(0.75)
	IQR = Q3 - Q1

	upper_limit : float = Q3 + (factor * IQR)
	lower_limit : float = Q1 - (factor * IQR)

	return lower_limit, upper_limit

def remove_outliers(dataframe : pd.DataFrame, factor : float = 1.5) -> pd.DataFrame:
	Q1 = dataframe.quantile(0.25)
	Q3 = dataframe.quantile(0.75)
	IQR = Q3 - Q1

	upper_limit : float = Q3 + (factor * IQR)
	lower_limit : float = Q1 - (factor * IQR)
	
	return dataframe.mask((dataframe > upper_limit) | (dataframe < lower_limit))

def main() -> None:
	#if len(sys.argv) < EXPECTED_ARGC:
	#	print("usage: graph_perf_logs <file_path>")
	#	exit()
	
	file_paths  : list[str]   = [
		"logs/without-ebpf-probe/node0-perf-2026-04-08_22-57-01.log",
		"logs/with-ebpf-probe/node0-perf-2026-04-08_22-53-26.log",
	]
	log_names   : list[str]   = ['Without ebpf-probe', 'With ebpf-probe']
	line_styles : list[str]   = ['solid', 'solid']
	line_widths : list[float] = [1.0, 1.0]

	figure = plt.figure(figsize=(20, 12))

	axis1 = plt.subplot2grid((2, 6), (0, 0), colspan=2)
	axis2 = plt.subplot2grid((2, 6), (0, 2), colspan=2)
	axis3 = plt.subplot2grid((2, 6), (0, 4), colspan=2)

	axis4 = plt.subplot2grid((2, 6), (1, 0), colspan=3)
	axis5 = plt.subplot2grid((2, 6), (1, 3), colspan=3)

	axes = [axis1, axis2, axis3, axis4, axis5]

	for line_style, line_width, file_path in zip(line_styles, line_widths, file_paths):
		data_frame = pd.read_csv(file_path, comment='#', header=None, na_values='na')
		data_frame.columns = ['timestamp', '2', 'value', '3', 'event', '5', '6', '7', '8']
		data_frame['timestamp'] = pd.to_datetime(data_frame['timestamp'])
		data_frame = data_frame.pivot_table(index='timestamp', columns='event', values='value', aggfunc='first')

		# Remove outliers by using Inter-Quartile Range (IQR)
		#data_frame = remove_outliers(data_frame, 5.0)

		# Resample
		#data_frame = data_frame.resample('10s').mean()

		# Normalize timestamps
		data_frame.index = (data_frame.index - data_frame.index.min()).total_seconds()
		
		data_frame['cache-misses'] = data_frame['cache-misses'] / 100_000
		data_frame['instructions'] = data_frame['instructions'] / 1_000_000
		data_frame['ref-cycles']   = data_frame['ref-cycles']   / 1_000_000

		# Plot
		data_frame['cache-misses']     .plot(ax=axis1, title='cache-misses', linewidth=line_width, linestyle=line_style)
		data_frame['instructions']     .plot(ax=axis2, title='instructions', linewidth=line_width, linestyle=line_style)
		data_frame['ref-cycles']       .plot(ax=axis3, title='ref-cycles',   linewidth=line_width, linestyle=line_style)

		color = axis1.get_lines()[-1].get_color()

		axis1_median = data_frame['cache-misses'].median()
		#axis1.axhline(y=axis1_median, color=color, linewidth=1.2, linestyle='dashed', label="Median")
		#axis1.text(x=axis1.get_xlim()[0], y=axis1_median, s=f'median', color=color, va='bottom', ha='left', fontsize=7)
		axis1.set_xlabel("Time (s)")
		axis1.set_ylabel("cache-misses (x100,000)")
		#axis1.set_ylim(get_interquartile_range(data_frame['cache-misses']))

		axis2_median = data_frame['instructions'].median()
		axis2.axhline(y=axis2_median, color=color, linewidth=1.2, linestyle='dashed', label="Median")
		axis2.text(x=axis2.get_xlim()[0], y=axis2_median, s=f'median', color=color, va='bottom', ha='left', fontsize=7)
		axis2.set_xlabel("Time (s)")
		axis2.set_ylabel("instructions (x1,000,000)")
		#axis2.set_ylim(get_interquartile_range(data_frame['instructions']))

		axis3_median = data_frame['ref-cycles'].median()
		axis3.axhline(y=axis3_median, color=color, linewidth=1.2, linestyle='dashed', label="Median")
		axis3.text(x=axis3.get_xlim()[0], y=axis3_median, s=f'median', color=color, va='bottom', ha='left', fontsize=7)
		axis3.set_xlabel("Time (s)")
		axis3.set_ylabel("ref-cycles (x1,000,000)")
		#axis3.set_ylim(get_interquartile_range(data_frame['ref-cycles']))

		data_frame['power/energy-pkg/'].plot(ax=axis4, title='power/energy-pkg/', linewidth=line_width, linestyle=line_style)
		data_frame['power/energy-ram/'].plot(ax=axis5, title='power/energy-ram/', linewidth=line_width, linestyle=line_style)

	for axis in axes:
		axis.ticklabel_format(useOffset=False, style='plain', axis='y')
		axis.tick_params(axis='x', labelsize=8)
		axis.grid(True, linestyle='--', alpha=0.5)

		#axis.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
	
	#axis1.set_ylim(bottom=1_000_000)
	#axis2.set_ylim(bottom=12_100_000_000, top=12_300_000_000)
	#axis3.set_ylim(bottom=16_000_000_000, top=18_000_000_000)

	axis1.yaxis.set_major_formatter(tkr.StrMethodFormatter('{x:,.0f}'))
	axis2.yaxis.set_major_formatter(tkr.StrMethodFormatter('{x:,.0f}'))
	axis3.yaxis.set_major_formatter(tkr.StrMethodFormatter('{x:,.0f}'))

	axis4.set_ylim(bottom=0.0)
	axis5.set_ylim(bottom=0.0)
	
	axis4.set_xlabel("Time (s)")
	axis4.set_ylabel("Joules")
	axis5.set_xlabel("Time (s)")
	axis5.set_ylabel("Joules")

	#figure.suptitle(" V.S. ".join(log_names))
	#figure.tight_layout()
	plt.subplots_adjust(hspace=0.30, wspace=0.50)
	plt.legend(log_names, loc="lower right")
	#plt.savefig("plot.pdf")
	plt.show()

if __name__ == '__main__':
	main()
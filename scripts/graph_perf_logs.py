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
		"logs/2026-04-05_16:31:09/node0-perf-2026-04-05_20-31-10.log",
		"logs/2026-04-05_16:18:26/node0-perf-2026-04-05_20-18-27.log",
		"logs/2026-04-07_11:12:30/node0-perf-2026-04-07_15-12-32.log",
	]
	log_names   : list[str]   = ['Without ebpf-probe', 'With ebpf-probe', 'Modifed ebpf-probe']
	line_styles : list[str]   = ['solid', 'solid', 'solid']
	line_widths : list[float] = [0.2, 0.3, 0.4]

	figure = plt.figure(figsize=(32, 16))

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
		data_frame = remove_outliers(data_frame, 5.0)

		# Resample
		data_frame = data_frame.resample('10s').mean()

		# Normalize timestamps
		data_frame.index = data_frame.index - data_frame.index.min()

		# Plot
		data_frame['cache-misses']     .plot(ax=axis1, title='cache-misses', linewidth=line_width, linestyle=line_style)
		data_frame['instructions']     .plot(ax=axis2, title='instructions', linewidth=line_width, linestyle=line_style)
		data_frame['ref-cycles']       .plot(ax=axis3, title='ref-cycles',   linewidth=line_width, linestyle=line_style)

		color = axis1.get_lines()[-1].get_color()

		axis1_median = data_frame['cache-misses'].median()
		axis1.axhline(y=axis1_median, color=color, linewidth=1.2, linestyle='dashed', label="Median")
		axis1.text(x=axis1.get_xlim()[0], y=axis1_median, s=f'median', color=color, va='bottom', ha='left', fontsize=7)

		axis2_median = data_frame['instructions'].median()
		axis2.axhline(y=axis2_median, color=color, linewidth=1.2, linestyle='dashed', label="Median")
		axis2.text(x=axis2.get_xlim()[0], y=axis2_median, s=f'median', color=color, va='bottom', ha='left', fontsize=7)

		axis3_median = data_frame['ref-cycles'].median()
		axis3.axhline(y=axis3_median, color=color, linewidth=1.2, linestyle='dashed', label="Median")
		axis3.text(x=axis3.get_xlim()[0], y=axis3_median, s=f'median', color=color, va='bottom', ha='left', fontsize=7)

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

	axis4.set_ylim(bottom=50.0)
	axis5.set_ylim(bottom=7.0)

	figure.suptitle(" V.S. ".join(log_names))
	figure.tight_layout()
	#plt.subplots_adjust(hspace=0.15, wspace=0.30)
	plt.legend(log_names, loc="lower right")
	#plt.savefig("plot.pdf")
	plt.show()

if __name__ == '__main__':
	main()
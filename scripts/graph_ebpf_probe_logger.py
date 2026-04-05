#!/usr/bin/env python3
import sys
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd

EXPECTED_ARGC = 2

def remove_outliers(dataframe : pd.DataFrame, factor : float = 1.5) -> pd.DataFrame:
	Q1 = dataframe.quantile(0.25)
	Q3 = dataframe.quantile(0.75)
	IQR = Q3 - Q1

	upper_limit : float = Q3 + factor * IQR
	lower_limit : float = Q1 - factor * IQR
	
	return dataframe.mask((dataframe > upper_limit) | (dataframe < lower_limit))

def main() -> None:
	if len(sys.argv) != EXPECTED_ARGC:
		print("usage: graph_ebpf_probe_logger <file_path>")
		exit()
	
	file_path : str = sys.argv[1]

	data_frame = pd.read_csv(file_path, comment='#', header=None, na_values='na')
	data_frame.columns = ['rx_bytes_received', 'instructions', 'cpu_cycles', 'ref_cpu_cycles', 'cache_misses', 'energy']
	data_frame['rx_bytes_received'] = data_frame['rx_bytes_received'] / (1 << 10)
	data_frame = data_frame.diff()

	figure, axes = plt.subplots(2, 3, figsize=(16, 8))
	data_frame['rx_bytes_received'].plot(ax=axes[0, 0], title="rx_bytes_received", ylabel="Throughput (KB/s)")
	data_frame['instructions']     .plot(ax=axes[0, 1], title="instructions")
	data_frame['cpu_cycles']       .plot(ax=axes[0, 2], title="cpu_cycles")
	data_frame['ref_cpu_cycles']   .plot(ax=axes[1, 0], title="ref_cpu_cycles")
	data_frame['cache_misses']     .plot(ax=axes[1, 1], title="cache_misses")
	data_frame['energy']           .plot(ax=axes[1, 2], title="energy")

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
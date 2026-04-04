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
        print("usage: graph_ipmi_logs <file_path>")
        exit()
    
    file_path : str = sys.argv[1]

    data_frame = pd.read_csv(file_path, comment='#', header=None, na_values='na')
    data_frame.columns = ['timestamp', 'sensor', 'value', 'unit', '5', '6', '7', '8', '9', '10', '11']
    data_frame = data_frame.pivot_table(index='timestamp', columns='sensor', values='value', aggfunc='first')
    data_frame.plot()

    print(data_frame)

    plt.title(file_path)
    plt.xlabel("Time")

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

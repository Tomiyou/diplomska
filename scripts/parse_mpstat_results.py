#!/usr/bin/python

import jc
import pandas as pd
import os

all_idles = pd.DataFrame()

def parse_file(input_file):
    print(input_file)

    f = open(input_file)
    lines = f.readlines()
    data = {}

    result = jc.parse('mpstat_s', lines)
    for i, item in enumerate(result):
        col_name = item['cpu']
        col_value = item['percent_idle'] / 100

        if col_name not in data:
            data[col_name] = [col_value]
        else:
            data[col_name].append(col_value)

    df = pd.DataFrame.from_dict(data, orient = 'index').transpose()

    # Keep only 50 iterations, starting at 5th
    df_len = len(df.index)
    df = df.drop(axis=0, labels=range(0, 5))
    df = df.drop(axis=0, labels=range(55, df_len))
    df = 100 - df

    # Vsota idle za 50 iteracij
    sum_of_idles = df.drop(['all'], axis=1).sum(axis=1)

    # Povprecje cez vse stolpce
    averages = df.mean()
    print("Average load for all CPUs", averages['all'])
    averages = averages.drop('all')
    print("Sum of load for each CPU", averages.sum())
    print(averages)
    # print(sum_of_idles)

    comps = (os.path.splitext(os.path.basename(input_file))[0]).split('_')
    all_idles[comps[0] + "_" + comps[1]] = sum_of_idles

    print()

files = [
    "logs_first_run/xdp_4core_mpstat.log",
    "logs_first_run/sfe_4core_mpstat.log",
    "logs_first_run/linux_4core_mpstat.log",

    "logs_first_run/xdp_2core_mpstat.log",
    "logs_first_run/sfe_2core_mpstat.log",
    "logs_first_run/linux_2core_mpstat.log",

    "logs_first_run/xdp_1core_mpstat.log",
    "logs_first_run/sfe_1core_mpstat.log",
    "logs_first_run/linux_1core_mpstat.log",
]

for file in files:
    parse_file(file)

all_idles.to_csv("all_idles.csv", float_format='%.2f')
print(all_idles.mean())

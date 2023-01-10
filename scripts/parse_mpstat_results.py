#!/usr/bin/python

import sys
import jc
import pandas as pd

input_file = sys.argv[1]
print(input_file)
output_file = input_file.rsplit(".", 1)[0] + ".csv"

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
df_len = len(df.index)
df = df.drop(axis=0, labels=range(0, 5))
df = df.drop(axis=0, labels=range(55, df_len))
averages = df.mean()
print("Average idle for all CPUs", averages['all'])
averages = averages.drop('all')
print("Sum of idle for each CPU", averages.sum())
print(averages)
print()
# df.to_csv(output_file)

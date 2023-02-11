#!/usr/bin/python

import jc
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import sys

all_idles = pd.DataFrame()

cores = sys.argv[1]

def format_time(x, _):
    try:
        # convert datetime64 to datetime, and use datetime's strftime:
        return "{:.0f}s".format(x*2)
    except IndexError:
        pass

def parse_file(input_file, accelerator):
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
    # df = df.drop(axis=0, labels=range(55, df_len))
    df = df.drop(df.tail(1).index)
    df = 100 - df

    # Vsota idle za 50 iteracij
    sum_of_idles = df.drop(['all'], axis=1).sum(axis=1)

    # # Povprecje cez vse stolpce
    # # averages = df.mean()
    # # print("Average load for all CPUs", averages['all'])
    # # averages = averages.drop('all')
    # # print("Sum of load for each CPU", averages.sum())
    # # print(averages)
    # print(sum_of_idles)

    all_idles[accelerator] = sum_of_idles

    # print()

for accelerator in ["linux", "sfe", "xdp"]:
    parse_file(f"logs/{accelerator}_{cores}core_mpstat.log", accelerator.upper())



# All idles
# all_idles.to_csv("all_idles.csv", float_format='%.2f')
print(all_idles)
print("CPU usage %")
print(all_idles[10:30].mean())

lines = all_idles.plot.line(figsize=(5, 2.5))
plt.gca().xaxis.set_major_formatter(format_time)
plt.gca().xaxis.set_minor_locator(mticker.AutoMinorLocator(2))
plt.gca().yaxis.set_major_formatter(mticker.PercentFormatter())
plt.gca().yaxis.set_major_locator(mticker.MultipleLocator(10 if cores == "4" else 20))
plt.gca().yaxis.set_minor_locator(mticker.AutoMinorLocator(2))
plt.grid(which='major')
plt.grid(which='minor', linestyle=':')
plt.tight_layout()
plt.savefig("cpu_usage_" + cores + ".png", dpi=300)



# Get linux vs everyone else
multipliers = pd.DataFrame()
for col in all_idles:
    multipliers[col] = (all_idles["LINUX"] + 1) / (all_idles[col] + 1)
multipliers[0:5] = 1
multipliers[35:40] = 1
print("Multipliers")
print(multipliers[10:30].mean())

lines = multipliers.plot.line(figsize=(5, 2.5))
plt.gca().xaxis.set_major_formatter(format_time)
plt.gca().xaxis.set_minor_locator(mticker.AutoMinorLocator(2))
plt.gca().yaxis.set_minor_locator(mticker.AutoMinorLocator(2))
plt.grid(which='major')
plt.grid(which='minor', linestyle=':')
plt.tight_layout()
plt.savefig("multipliers_" + cores + ".png", dpi=300)
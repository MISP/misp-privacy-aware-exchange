#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script to generate graphs from csv
x in function of y
"""
import argparse, configparser
import pandas as pd
import csv

###################
# Parse Arguments #
###################

parser = argparse.ArgumentParser(description='Create an encrypted IOC \
                rule.')
parser.add_argument('--csv', dest='filename', default='error',
                help='csv filename')
parser.add_argument('-x', type=int, default=0,
                help='column number for x axis')
parser.add_argument('-y', type=int, default=1,
                help='column number for y axis')
parser.add_argument('-t', '--title', default= "",
                help='graph title')
args = parser.parse_args()


################
# Parse values #
################
dict_graph = {}
with open(args.filename, 'r') as csvfile:
    csv_data = csv.reader(csvfile, delimiter=',')
    first = True
    namex = ""
    namey = ""
    x = []
    y = []
    for row in csv_data:
        if first:
            namex = row[args.x]
            namey = row[args.y]
        else:
            x.append(float(row[args.x]))
            y.append(float(row[args.y]))
        first = False

s = pd.Series(y, index=x)
df = pd.DataFrame(s)
fig = df.plot()
fig.set_xlabel(namex)
fig.set_ylabel(namey)
if not args.title == "":
    fig.set_title(args.title)
fig = fig.get_figure()
fig.savefig(args.filename + ".png")

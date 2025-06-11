import csv
import os
import json
from io import StringIO
from collections import defaultdict

BASE = os.path.dirname(__file__)

# Read the CSV using csv.reader
f = open(os.path.join(BASE, 'dgie_eval.csv'))
reader = csv.reader(f)

# Get header and trim to the first 6 fields
headers = next(reader)[:6]

# Parse the rows
data = []
for row in reader:
    trimmed_row = row[:6]
    entry = dict(zip(headers, trimmed_row))
    data.append(entry)

d2all = defaultdict(list)
d2ab = defaultdict(list)
d2st = defaultdict(list)
d2compl =	defaultdict(list)

for entry in data:
	d = entry['device']
	s = entry['servcie']
	d2all[d].append(s)
	if entry['Ab'] == 'y':
		d2ab[d].append(s)
	if entry['St'] == 'y':
		d2st[d].append(s)
	if entry['St'] == 'y' and entry['Ab'] == 'y':
		d2compl[d].append(s)

print(f'\t\t\t# Services\t#Si\t#Ab\t#St\t#Compliant')
for d in d2all:
	indents = 2
	if len(d) == 16:
		indents = 1
	print(f'{d}{indents*"\t"}{len(d2all[d])}\t\t{len(d2all[d])}\t{len(d2ab[d])}\t{len(d2st[d])}\t{len(d2compl[d])}\t{len(d2compl[d])/len(d2all[d])*100}%')

print(f'overall\t\t\t{sum(len(value) for value in d2all.values())}\t\t{sum(len(value) for value in d2all.values())}\t{sum(len(value) for value in d2ab.values())}\t{sum(len(value) for value in d2st.values())}\t{sum(len(value) for value in d2compl.values())}\t{(sum(len(value) for value in d2compl.values()))/(sum(len(value) for value in d2all.values()))*100}%')

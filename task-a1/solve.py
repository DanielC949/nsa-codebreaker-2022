#!/usr/bin/python3

import csv
from dateutil import parser
from datetime import timedelta

r = csv.reader(open('vpn.log', 'r'))

kv = [colname for colname in next(r)]
data = []

for row in r:
    data.append({kv[i]: row[i] for i in range(len(row))})

people = {}
for d in data:
    if not d['Error'] == '':
        continue
    user = d['Username']
    s = parser.parse(d['Start Time'], tzinfos={'EDT':0})
    e = s + timedelta(seconds=int(d['Duration']))

    if user in people:
        logins = people[user]
        for (ls, le) in logins:
            if (s <= ls and e >= ls) or (s >= ls and s <= le):
                print(user)
        people[user].append((s, e))
    else:
        people[user] = [(s, e)]
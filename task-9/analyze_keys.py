#!/usr/bin/python3

import base64
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime, timezone

key = base64.b64decode('daZM0SBydGCZPJ6T51MuwIusahHjJCwlaIOENQdvIxg=')
con = sqlite3.connect('keyMaster.db')

rows = con.execute('select customerId, encryptedKey, creationDate from customers order by creationDate').fetchall()

with open('keygeneration.log', 'r') as f:
    logrows = {int((sl:=l[:-1].split('\t'))[2]):sl for l in f.readlines()}

uuid_epoch = datetime(1582, 10, 15, tzinfo=timezone.utc)
for (cid, enckey, cdate) in rows:
    decode_key = base64.b64decode(enckey)
    iv = decode_key[:16]
    ct = decode_key[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt_key = unpad(cipher.decrypt(ct), 16)
    uuid_timestamp = int(pt_key[15:18] + pt_key[9:13] + pt_key[:8], 16)
    if cid not in logrows:
        print(f'{cid} not found!')
        exit(1)
    lrow = logrows[cid]
    dt = datetime.fromisoformat(lrow[0]) - datetime.fromisoformat(cdate)
    print(cid, cdate, pt_key, dt)

con.close()
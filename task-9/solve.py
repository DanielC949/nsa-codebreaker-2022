#!/usr/bin/python3

from datetime import datetime, timedelta, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time

file = 'important_data'

with open(file + '.pdf.enc', 'rb') as pdf_file:
    pdf_raw = pdf_file.read()
    pdf_file.close()
pdf_iv = int(pdf_raw[:32].decode('US_ASCII'), 16).to_bytes(16, 'big')
print('iv:', pdf_iv)
pdf_enc = pdf_raw[32:]

def try_key(key):
    assert len(key) == 16
    cipher = AES.new(key, AES.MODE_CBC, iv=pdf_iv)
    raw_dec = cipher.decrypt(pdf_enc)
    if raw_dec[-1] < 1 or raw_dec[-1] >= 16:
        return False
    try:
        dec = unpad(raw_dec, 16)
        if dec[:4] == b'%PDF':
            print('\n!!FOUND KEY!!:', key)
            with open(file + '_DEC.pdf', 'wb') as out:
                out.write(dec)
                out.close()
                return True
    except ValueError:
        return False

def uuid_dec():
    t_offset, t_duration = 11, 5
    d = datetime.fromisoformat('2022-04-04T11:38:23-04:00').astimezone(tz=timezone.utc)
    dt = d - datetime(1582, 10, 15, tzinfo=timezone.utc)
    uuid_time_start = int((dt - timedelta(seconds=t_offset)) / timedelta(microseconds=1)) * 10

    for i in range(uuid_time_start, uuid_time_start + t_duration * 10000000 + 1):
        t = hex(i)[2:]
        key = (t[7:] + '-' + t[3:7] + '-1' + t[0]).encode()
        if i % 143273 == 0:
            print(key, end='\r')
        if try_key(key):
            return (True, i - uuid_time_start + 1)
    return (False, i - uuid_time_start + 1)

ts = time.perf_counter()
res, nkeys = uuid_dec()
if not res:
    print('\nunlucky')
print(f'elapsed sec: {time.perf_counter() - ts}, tested {nkeys} keys')
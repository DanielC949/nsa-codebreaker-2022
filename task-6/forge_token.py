#!/usr/bin/python3

import jwt
from datetime import datetime, timedelta
import sys

hmac_key = 'mnkor8J5UOeJKAqN2yx9MOkDOehyDKdt'

user_secrets = {
    16963: 'raZRtut2P4uNdv2J5lNb6ZbjGmiQwPQy', # LamentableConservative
    9076: 'HAEu7PiO8mq7g43xMXKdJUVvajbde8pK'   # HelpfulHandball
}

try:
    uid = int(sys.argv[1])
    if uid not in user_secrets:
        print(f'Unknown uid {uid}')
        exit(1)
except ValueError:
    print(f'Invalid uid {sys.argv[1]}')
    exit(1)
except IndexError:
    print('No uid given')
    exit(1)

now = datetime.now()
expire = now + timedelta(days=30)

claims = {
    'iat': now,
    'exp': expire,
    'uid': uid,
    'sec': user_secrets[uid]
}
tok = jwt.encode(claims, hmac_key, algorithm='HS256').decode()

domain = 'xekflqhmhrsoelot.ransommethis.net'
print(f'# Netscape HTTP Cookie File\n{domain}\tFALSE\t/\tTRUE\t2145916800\ttok\t{tok} ')
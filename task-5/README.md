# Task 5

## Background
> The FBI knew who that was, and got a warrant to seize their laptop. It looks like they had an encrypted file, which may be of use to your investigation.
>
> We believe that the attacker may have been clever and used the same RSA key that they use for SSH to encrypt the file. We asked the FBI to take a core dump of `ssh-agent` that was running on the attacker's computer.
>
> Extract the attacker's private key from the core dump, and use it to decrypt the file.
>
> _Hint: if you have the private key in PEM format, you should be able to decrypt the file with the command `openssl pkeyutl -decrypt -inkey privatekey.pem -in data.enc`_
> ### Downloads
> - Core dump of ssh-agent from the attacker's computer (`core`)
> - ssh-agent binary from the attacker's computer. The computer was running Ubuntu 20.04. (`ssh-agent`)
> - Encrypted data file from the attacker's computer (`data.enc`)
> ### Prompt
> Enter the token value extracted from the decrypted file

## Writeup
TL;DR: Find the shield prekey and shielded private key from the core dump, unshield it using `ssh-keygen` (compiled with symbols), save it into a PEM file, decrypt the data file, and get the cookie value.

This one was probably the most complicated task for me in the challenge. I started by looking up how people have tried to recover SSH keys from `ssh-agent` core dumps. I found two useful blog posts: [one from 2009 by vnhacker](https://vnhacker.blogspot.com/2009/09/sapheads-hackjam-2009-challenge-6-or.html), and [one from 2021 by Piergiovanni Cipolloni](https://security.humanativaspa.it/openssh-ssh-agent-shielded-private-key-extraction-x86_64-linux/). While Cipolloni gives a script to do the entire extraction process, it requires the key comment, which we unfortunately don't have (and it wouldn't be much fun if it did work, anyways). vnhacker gives a way to start: by looking for the socket name used by `ssh-agent` to communicate with other binaries. It seems to take the form of `"/tmp/ssh-<some random alphanumeric string>/agent.<pid>"`. Normally, this wouldn't help us too much, since we wouldn't know how `ssh-agent`'s memory is laid out. However, we can easily find the source code on Github, and from there figure out where the important variables are.

Looking at the [source code](https://github.com/openssh/openssh-portable/blob/15a01cf15f396f87c6d221c5a6af98331c818962/ssh-agent.c#L155), we can see this.
```c
/* private key table */
struct idtable *idtab;

int max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
char socket_name[PATH_MAX];
char socket_dir[PATH_MAX];
```

We're really interested in `idtab`, since it contains all the identities for this instance of `ssh-agent`. We know that it should be a few bytes before `socket_name`, so we can start by looking for that. Since it's a global variable, it should live in the `.bss` section. After loading the core file into GDB, searching for it is as easy as
```
(gef)  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
...
0x000056153bd10000 0x000056153bd10050 0x0000000000055000 -w- .data
0x000056153bd10060 0x000056153bd12830 0x0000000000055050 --- .bss
0x0000000000000000 0x0000000000000034 0x0000000000055050 r-- .gnu_debuglink
...
(gef)  grep "/tmp/ssh" little 0x56153bd10060-0x56153bd12830
[+] Searching '/tmp/ssh' in 0x56153bd10060-0x56153bd12830
[+] In '.bss'(0x56153bd10060-0x56153bd12830), permission=---
  0x56153bd107e0 - 0x56153bd107fe  →   "/tmp/ssh-lKZUdUvEXl91/agent.18"
  0x56153bd11820 - 0x56153bd11835  →   "/tmp/ssh-lKZUdUvEXl91"
```

The first match is `socket_name`, and the second should be `socket_dir`. Dumping the bytes before the start of `socket_name` gives
```
(gef)  x/20wx 0x56153bd107e0-48
0x56153bd107b0: 0x00000000      0x00000000      0x00000000      0x00000000
0x56153bd107c0: 0x3c6c43c0      0x00005615      0x00000000      0x00000000
0x56153bd107d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x56153bd107e0: 0x706d742f      0x6873732f      0x5a4b6c2d      0x76556455
0x56153bd107f0: 0x396c5845      0x67612f31      0x2e746e65      0x00003831
```

There's only one pointer-looking thing (`0x56153c6c43c0`), which is probably `idtab`, so let's look there.

<table>
<tr>
<td>

```
(gef)  x/6wx 0x56153c6c43c0
0x56153c6c43c0: 0x00000001      0x00000000
0x56153c6c43c8: 0x3c6c9120      0x00005615
0x56153c6c43d0: 0x3c6c9120      0x00005615
```

</td>
<td>

from [`ssh-agent.c`](https://github.com/openssh/openssh-portable/blob/15a01cf15f396f87c6d221c5a6af98331c818962/ssh-agent.c#L150):
```c
struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};
```
from [`sys-queue.h`](https://github.com/openssh/openssh-portable/blob/15a01cf15f396f87c6d221c5a6af98331c818962/openbsd-compat/sys-queue.h#L502):
```c
#define TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}
```

</td>
</tr>
</table>

We can see that this instance of `ssh-agent` has one identity, located at `0x56153c6c9120` (keeping in mind that struct members will be aligned on 8-byte boundaries). Looking at this entry, we see

<table>
<tr>
<td>

```
(gef)  x/20wx 0x56153c6c9120
0x56153c6c9120: 0x00000000      0x00000000
0x56153c6c9128: 0x3c6c43c8      0x00005615
0x56153c6c9130: 0x3c6c7ee0      0x00005615
0x56153c6c9138: 0x3c6c5c00      0x00005615
0x56153c6c9140: 0x00000000      0x00000000
0x56153c6c9148: 0x00000000      0x00000000
0x56153c6c9150: 0x00000000      0x00000000
0x56153c6c9158: 0x00000000      0x00000000
0x56153c6c9160: 0x00000000      0x00000000
0x56153c6c9168: 0x00000021      0x00000000
```

</td>
<td>

from [`ssh-agent.c`](https://github.com/openssh/openssh-portable/blob/15a01cf15f396f87c6d221c5a6af98331c818962/ssh-agent.c#L138):
```c
typedef struct identity {
	TAILQ_ENTRY(identity) next;
	struct sshkey *key;
	char *comment;
	char *provider;
	time_t death;
	u_int confirm;
	char *sk_provider;
	struct dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;
```
from [`sys-queue.h`](https://github.com/openssh/openssh-portable/blob/15a01cf15f396f87c6d221c5a6af98331c818962/openbsd-compat/sys-queue.h#L511):
```c
#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}
```

</td>
</tr>
</table>

Most of the fields in the identity don't really matter to us; we just want the SSH key, which should be at `0x56153c6c7ee0`. Looking there, we find

<table>
<tr>
<td>

```
(gef)  x/42wx 0x56153c6c7ee0
0x56153c6c7ee0: 0x00000000      0x00000000
0x56153c6c7ee8: 0x3c6cb0e0      0x00005615
0x56153c6c7ef0: 0x00000000      0x00000000
0x56153c6c7ef8: 0xffffffff      0x00000000
0x56153c6c7f00: 0x00000000      0x00000000
0x56153c6c7f08: 0x00000000      0x00000000
0x56153c6c7f10: 0x00000000      0x00000000
0x56153c6c7f18: 0x00000000      0x00000000
0x56153c6c7f20: 0x00000000      0x00000000
0x56153c6c7f28: 0x00000000      0x00000000
0x56153c6c7f30: 0x00000000      0x00000000
0x56153c6c7f38: 0x00000000      0x00000000
0x56153c6c7f40: 0x00000000      0x00000000
0x56153c6c7f48: 0x00000000      0x00000000
0x56153c6c7f50: 0x00000000      0x00000000
0x56153c6c7f58: 0x00000000      0x00000000
0x56153c6c7f60: 0x00000000      0x00000000
0x56153c6c7f68: 0x3c6caab0      0x00005615
0x56153c6c7f70: 0x00000570      0x00000000
0x56153c6c7f78: 0x3c6cbc00      0x00005615
0x56153c6c7f80: 0x00004000      0x00000000
```

</td>
<td>

from [`sshkey.h`](https://github.com/openssh/openssh-portable/blob/15a01cf15f396f87c6d221c5a6af98331c818962/sshkey.h#L125):
```c
struct sshkey {
	int	 type;
	int	 flags;
	/* KEY_RSA */
	RSA	*rsa;
	/* KEY_DSA */
	DSA	*dsa;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	int	 ecdsa_nid;	/* NID of curve */
	EC_KEY	*ecdsa;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_XMSS */
	char	*xmss_name;
	char	*xmss_filename;	/* for state file updates */
	void	*xmss_state;	/* depends on xmss_name, opaque */
	u_char	*xmss_sk;
	u_char	*xmss_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	char	*sk_application;
	uint8_t	sk_flags;
	struct sshbuf *sk_key_handle;
	struct sshbuf *sk_reserved;
	/* Certificates */
	struct sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};
```

</td>
</tr>
</table>

There's the RSA key, at `0x56153c6cb0e0`!

<table>
<tr>
<td>

```
(gef)  x/64wx 0x56153c6cb0e0
0x56153c6cb0e0: 0x00000000      0x00000000
0x56153c6cb0e8: 0xae09fe80      0x00007f2c
0x56153c6cb0f0: 0x00000000      0x00000000
0x56153c6cb0f8: 0x3c6c62b0      0x00005615
0x56153c6cb100: 0x3c6c7ca0      0x00005615
0x56153c6cb108: 0x00000000      0x00000000
0x56153c6cb110: 0x00000000      0x00000000
0x56153c6cb118: 0x00000000      0x00000000
0x56153c6cb120: 0x00000000      0x00000000
0x56153c6cb128: 0x00000000      0x00000000
0x56153c6cb130: 0x00000000      0x00000000
0x56153c6cb138: 0x00000000      0x00000000
0x56153c6cb140: 0x00000000      0x00000000
0x56153c6cb148: 0x00000000      0x00000000
0x56153c6cb150: 0x00000001      0x00000006
0x56153c6cb158: 0x00000000      0x00000000
0x56153c6cb160: 0x00000000      0x00000000
0x56153c6cb168: 0x00000000      0x00000000
0x56153c6cb170: 0x00000000      0x00000000
0x56153c6cb178: 0x00000000      0x00000000
0x56153c6cb180: 0x00000000      0x00000000
0x56153c6cb188: 0x3c6c9320      0x00005615
0x56153c6cb190: 0x00000000      0x00000000
0x56153c6cb198: 0x00000751      0x00000000
0x56153c6cb1a0: 0xaddca0a0      0x00007f2c
0x56153c6cb1a8: 0xaddca0a0      0x00007f2c
0x56153c6cb1b0: 0x3c6cb190      0x00005615
0x56153c6cb1b8: 0x3c6cb190      0x00005615
0x56153c6cb1c0: 0x00000000      0x00000000
0x56153c6cb1c8: 0x00000000      0x00000000
0x56153c6cb1d0: 0x00000000      0x00000000
0x56153c6cb1d8: 0x00000000      0x00000000
```

</td>
<td>

from [`openssl/crypto/rsa/rsa_local.h`](https://github.com/openssl/openssl/blob/3f32d29ad464591ed968a1e430111e1525280f4c/crypto/rsa/rsa_local.h#L48):
```c
struct rsa_st {
    /*
     * #legacy
     * The first field is used to pickup errors where this is passed
     * instead of an EVP_PKEY.  It is always zero.
     * THIS MUST REMAIN THE FIRST FIELD.
     */
    int dummy_zero;

    OSSL_LIB_CTX *libctx;
    int32_t version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;

    /*
     * If a PSS only key this contains the parameter restrictions.
     * There are two structures for the same thing, used in different cases.
     */
    /* This is used uniquely by OpenSSL provider implementations. */
    RSA_PSS_PARAMS_30 pss_params;

#if defined(FIPS_MODULE) && !defined(OPENSSL_NO_ACVP_TESTS)
    RSA_ACVP_TEST *acvp_test;
#endif

#ifndef FIPS_MODULE
    /* This is used uniquely by rsa_ameth.c and rsa_pmeth.c. */
    RSA_PSS_PARAMS *pss;
    /* for multi-prime RSA, defined in RFC 8017 */
    STACK_OF(RSA_PRIME_INFO) *prime_infos;
    /* Be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
#endif
    CRYPTO_REF_COUNT references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
    CRYPTO_RWLOCK *lock;

    int dirty_cnt;
};
```

</td>
</tr>
</table>

That doesn't look right, all the important parts (`d`, `p`, and `q`, specifically) are `NULL` (0)! This is when Cipolloni's article comes in handy. Apparently, OpenSSH "recently" (2019) implemented a concept called "shielded private keys" to defend against attacks like Spectre and Meltdown. Basically, private key shielding encrypts the private keys with a key derived from 16KB of random data, called the "prekey". The shielded key is only decrypted when it needs to be used. Because the prekey is so large, the bit errors accumulated when using these attacks make it impossible to recover the entire prekey and thus be able to unshield the private key(s). We're not relying on those side-channel attacks, so we can go right on ahead.

From the `struct sshkey` we got earlier, we know that the shielded private key data is the `0x570` bytes starting at `0x56153c6caab0`, and the prekey is `0x4000` bytes starting at `0x56153c6cbc00`. We can simply write these bytes out to a file.
```
(gef)  python
>f = open('shielded_private', 'wb')
>f.write(gdb.inferiors()[0].read_memory(0x56153c6caab0, 0x570).tobytes())
>f.close()
>f = open('shield_prekey', 'wb')
>f.write(gdb.inferiors()[0].read_memory(0x56153c6cbc00, 0x4000).tobytes())
>f.close()
```

From here on out, we can follow Cipolloni almost exactly. We can build `ssh-keygen` with debugging symbols to easily unshield the private key for us.
```bash
$ tar xvfz openssh-9.0p1.tar.gz
$ cd openssh-9.0p1
$ ./configure --with-audit=debug && make ssh-keygen
...
$ gdb -q ./ssh-keygen
```

Then, getting the private key out is relatively simple.
```
(gef)  b main
(gef)  b sshkey_free
(gef)  r
...
(gef)  set $k = (struct sshkey *)sshkey_new(0)
(gef)  set $shielded_private = (unsigned char *)malloc(0x570)
(gef)  set $shield_prekey = (unsigned char *)malloc(0x4000)
(gef)  set $fd = fopen("shielded_private", "r")
(gef)  call fread($shielded_private, 1, 0x570, $fd)
$1 = 0x570
(gef)  call fclose($fd)
$2 = 0x0
(gef)  set $fd = fopen("shield_prekey", "r")
(gef)  call fread($shield_prekey, 1, 0x4000, $fd)
$3 = 0x4000
(gef)  call fclose($fd)
$4 = 0x0
(gef)  set $k->shielded_private = $shielded_private
(gef)  set $k->shielded_len = 0x570
(gef)  set $k->shield_prekey = $shield_prekey
(gef)  set $k->shield_prekey_len = 0x4000
(gef)  call sshkey_unshield_private($k)
...
(gef)  frame 1
(gef)  call sshkey_save_private(*kp, "plain_key", "", "", 1, 0, 0)
$5 = 0x0
```

The only difference to Cipolloni's GDB commands is using 1 instead of 0 for the fifth argument of `sshkey_save_private`; this just saves the key in PEM format instead of OpenSSH format, which is needed in order to use the command given in the hint as-is.
```
$ openssl pkeyutl -decrypt -inkey plain_key -in data.enc > data.dec
$ cat data.dec
# Netscape HTTP Cookie File
xekflqhmhrsoelot.ransommethis.net       FALSE   /       TRUE    2145916800      tok     eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTI4MjY4MDgsImV4cCI6MTY1NTQxODgwOCwic2VjIjoicmFaUnR1dDJQNHVOZHYySjVsTmI2WmJqR21pUXdQUXkiLCJ1aWQiOjE2OTYzfQ.VGKRAm6p6e3Z0DM7wPohSyfSDgNMqsRIzS2cWpmhBPM
```

We see it's a cookie file, and the cookie's value is the long base-64 encoded string. Putting this into the answer box, we get our task 5 badge!
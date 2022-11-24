# Task A2

## Background
> Using the timestamp and IP address information from the VPN log, the FBI was able to identify a virtual server that the attacker used for staging their attack. They were able to obtain a warrant to search the server, but key files used in the attack were deleted.
>
> Luckily, the company uses an intrusion detection system which stores packet logs. They were able to find an SSL session going to the staging server, and believe it may have been the attacker transferring over their tools.
> 
> The FBI hopes that these tools may provide a clue to the attacker's identity
> ### Downloads
> - Files captured from root's home directory on the staging server (`root.tar.bz2`)
> - PCAP file believed to be of the attacker downloading their tools (`session.pcap`)
> ### Prompt
> What was the username of the account the attacker used when they built their tools?

## Writeup
**TL;DR**: Use root's certificate from the staging server to decrypt the TLS session for `GET /tools.tar`, then get the username from the tarball.

First things first, let's extract the bzip. We can see that there are a couple things, the main one being `runwww.py`, which runs an HTTPS server for file transfer. This uses `.cert.pem` as the certificate, which is conveniently included in the bzip.

Sticking the PCAP into Wireshark, we can see an HTTP GET for `tools.tar`, but the actual data is protected by TLS. However, since we have the PEM used for this server, we can get Wireshark to decrypt the stream for us by adding it as an RSA private key (under `Edit -> Preferences -> RSA Keys -> Add new keyfile...`). Now, we can follow the decrypted TLS stream for the GET request, and just looking at the first couple tar bytes, we see something that looks like a username: "LewdNiftyMango". Putting this into the answer box, we get our task A2 badge!

## Additional notes
If we wanted to be extra sure that the username is correct, we can take a look at the TAR format. From the [Wikipedia page](https://en.wikipedia.org/wiki/Tar_(computing)#UStar_format), it looks like our file should more accurately be in the UStar format, which should have the owner username at byte offset 265 (0x109).
```
$ tail -c +265 tools.tar | head -c 32 | xxd
00000000: 004c 6577 644e 6966 7479 4d61 6e67 6f00  .LewdNiftyMango.
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```
We can see that the owner is in fact "LewdNiftyMango".
# Task A1

## Background
> We believe that the attacker may have gained access to the victim's network by phishing a legitimate users credentials and connecting over the company's VPN. The FBI has obtained a copy of the company's VPN server log for the week in which the attack took place. Do any of the user accounts show unusual behavior which might indicate their credentials have been compromised?
>
> Note that all IP addresses have been anonymized. 
>
> ### Downloads
> - Access log from the company's VPN server for the week in question (`vpn.log`)
> ### Prompt
> Enter the username which shows signs of a possible compromise.

## Writeup
**TL;DR**: Find the user who has two overlapping VPN sessions.

So we're given a CSV of the VPN logins for the employees of the victim company. The first thing to notice is some of the entries are failures due to "LDAP invalid credentials". However, multiple users have this failure, and we know from the background that the attacker phished a user's credentials, so this is probably not the unusual behavior that we are looking for. For similar reasons, the entries with "user not found" probably aren't helpful, and due to the IP address anonymization, the "Real IP" field doesn't give us any useful information.

This basically leaves "Start Time", "Duration", and "Bytes Total" left as possible clues. We could use total bytes and duration to get an average data rate, but this approach seems unlikely to be helpful, since ransomware shouldn't really have a large network footprint. Therefore, we should look at when people are logged in to the VPN.

By recording the start and end time for each VPN session, we can find if any sessions overlap, which would be a pretty good indicator of something fishy.
```bash
$ python3 solve.py
Frances.S
```

Luckily, there is only one person with overlapping VPN sessions, and when we put this username into the answer box, we get our task A1 badge!
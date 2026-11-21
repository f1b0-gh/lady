#!/usr/bin/env python3
"""Initialize only the disposable instance's local administrator; never import data."""
import argparse
import json
import os
from pathlib import Path
import secrets
import urllib.error
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--base-url", default="http://127.0.0.1:18081")
parser.add_argument("--credentials", type=Path, required=True)
args = parser.parse_args()
if args.base_url != "http://127.0.0.1:18081":
    parser.error("This recipe only targets the explicit local qualification endpoint")
if args.credentials.exists():
    parser.error("Credentials already exist; preserve them and use the existing session")
# Reserve a private file before modifying the server. Preserve the password if
# login fails after a successful password change so initialization is recoverable.
fd = os.open(args.credentials, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
credentials = {"base_url": args.base_url, "username": "admin", "password": secrets.token_urlsafe(32)}
with os.fdopen(fd, "w") as stream:
    json.dump(credentials, stream)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise ValueError("Local administrator initialization refuses redirects")

# Credentials must never reach an environment proxy or a redirected endpoint.
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

def post(endpoint, values):
    request = urllib.request.Request(args.base_url + endpoint,
        data=urllib.parse.urlencode(values).encode(), method="POST")
    with opener.open(request, timeout=30) as response:
        return response.read().decode()

try:
    post("/api/v1/user/forceChangePassword", {
        "username": "admin", "password": "admin",
        "newPassword": credentials["password"], "confirmPassword": credentials["password"]})
    credentials["bearer_token"] = post("/api/v1/user/login", {
        "username": "admin", "password": credentials["password"]})
    with args.credentials.open("w") as stream:
        json.dump(credentials, stream)
except urllib.error.HTTPError as error:
    error.close()
    raise SystemExit(f"Initialization stopped at HTTP {error.code}; private recovery credentials retained") from None
print("Private qualification credentials stored at", args.credentials)

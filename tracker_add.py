#!/usr/bin/python
# SPDX-License-Identifier: MIT

import getpass
import json
import os
import requests
import sys
from getpass import getpass
from lxml import etree

# e.g. TRACKER_URL='http://127.0.0.32:5000' for local testing purposes
TRACKER_URL = os.environ.get("TRACKER_URL") or "https://security.archlinux.org"

username = os.environ.get("TRACKER_USERNAME")
password = os.environ.get("TRACKER_PASSWORD")
while username is None or username == "\n":
    open("/dev/tty", "w").write("Arch Linux Security Tracker username: ")
    username = open("/dev/tty", "r").readline()
while password is None or password == "":
    password = getpass("Arch Linux Security Tracker password: ")

session = requests.session()

csrf_token = session.get(f"{TRACKER_URL}/login").content
csrf_token = etree.fromstring(csrf_token, etree.HTMLParser())
csrf_token = csrf_token.xpath('string(//input[@id="csrf_token"]/@value)')

# This can happen in my test setup, I haven't observed it in production yet,
# might be a Flask bug
if "session" not in session.cookies:
    print("Missing session cookie, cannot login")
    sys.exit()

response = session.post(
    f"{TRACKER_URL}/login",
    data={"csrf_token": csrf_token, "username": username, "password": password},
)
if not response.ok:
    error = etree.fromstring(response.content, etree.HTMLParser())
    error = error.xpath('string(//div[@class="errors"]/ul/li/text())')
    print(f"Login failure: {error}")
    sys.exit()

cves = json.loads("\n".join(sys.stdin.readlines()))

for cve in cves:
    print(f"Adding {cve['name']}...")
    data = {
        "csrf_token": csrf_token,
        "cve": cve["name"],
        "issue_type": cve["type"].lower() or "unknown",
        "severity": cve["severity"].lower() or "unknown",
        "remote": cve["vector"].lower() or "unknown",
        "description": cve["description"] or "",
        "reference": "\n".join(cve["references"] or ""),
        "notes": cve["notes"] or "",
    }
    response = session.post(f"{TRACKER_URL}/cve/add", data=data, allow_redirects=False)
    if response.status_code != 302:
        warning = etree.fromstring(response.content, etree.HTMLParser())
        warning = warning.xpath('string(//div[@class="box warning"]/text())')
        print(f"Failed to add {cve['name']}: {warning}")
    elif "/login" in response.headers["Location"]:
        print(f"Failed to add {cve['name']} due to an authentication failure")

session.get(f"{TRACKER_URL}/logout")

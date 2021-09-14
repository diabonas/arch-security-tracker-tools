# SPDX-License-Identifier: MIT

import click
import json
import requests
from lxml import etree


@click.command()
@click.option(
    "--username",
    prompt="Arch Linux Security Tracker username",
    envvar="TRACKER_USERNAME",
    help="username for the security tracker (will be prompted if missing)",
)
@click.option(
    "--password",
    prompt="Arch Linux Security Tracker password",
    hide_input=True,
    envvar="TRACKER_PASSWORD",
    help="password for the security tracker (will be prompted if missing)",
)
@click.option(
    "--tracker-url",
    default="https://security.archlinux.org",
    envvar="TRACKER_URL",
    help="URL for the security tracker (defaults to https://security.archlinux.org)",
)  # e.g. 'http://127.0.0.32:5000' for local testing purposes
@click.argument("input", type=click.File("r"), default=click.get_text_stream("stdin"))
def add(username, password, tracker_url, input):
    """Add a list of CVEs provided in JSON format to the security tracker"""
    session = requests.session()

    csrf_token = session.get(f"{tracker_url}/login").content
    csrf_token = etree.fromstring(csrf_token, etree.HTMLParser())
    csrf_token = csrf_token.xpath('string(//input[@id="csrf_token"]/@value)')

    # This can happen in my test setup, I haven't observed it in production yet,
    # might be a Flask bug
    if "session" not in session.cookies:
        click.echo("Missing session cookie, cannot login", err=True)
        return

    response = session.post(
        f"{tracker_url}/login",
        data={"csrf_token": csrf_token, "username": username, "password": password},
    )
    if not response.ok:
        error = etree.fromstring(response.content, etree.HTMLParser())
        error = error.xpath('string(//div[@class="errors"]/ul/li/text())')
        click.echo(f"Login failure: {error}", err=True)
        return

    cves = json.loads("\n".join(input.readlines()))

    for cve in cves:
        click.echo(f"Adding {cve['name']}...")
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
        response = session.post(
            f"{tracker_url}/cve/add", data=data, allow_redirects=False
        )
        if response.status_code != 302:
            warning = etree.fromstring(response.content, etree.HTMLParser())
            warning = warning.xpath('string(//div[@class="box warning"]/text())')
            click.echo(f"Failed to add {cve['name']}: {warning}", err=True)
        elif "/login" in response.headers["Location"]:
            click.echo(
                f"Failed to add {cve['name']} due to an authentication failure",
                err=True,
            )
            break

    session.get(f"{tracker_url}/logout")

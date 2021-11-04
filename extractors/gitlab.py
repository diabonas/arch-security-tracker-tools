# SPDX-License-Identifier: MIT

import json
import re

import click
import requests

VECTORS = {
    "NETWORK": "Remote",
    "ADJACENT_NETWORK": "Remote",
    "LOCAL": "Local",
    "PHYSICAL": "Local",
}


@click.command()
@click.argument("cve", nargs=-1)
@click.option(
    "--output",
    type=click.File("w"),
    default=click.get_text_stream("stdout"),
    help="Output file with CVEs in JSON format (defaults to stdout)",
)
def gitlab(cve, output):
    """Extract CVEs assigned by the GitLab CNA"""
    cves = []
    for cve_number in cve:
        year = re.match("CVE-([0-9]*)-[0-9]*", cve_number).group(1)
        api_endpoint = (
            f"https://gitlab.com/gitlab-org/cves/-/raw/master/{year}/{cve_number}.json"
        )

        request = requests.get(api_endpoint)
        if not request.ok:
            click.echo(f"{cve_number} not found!", err=True)
            continue

        cve = json.loads(request.content)

        cve = {
            "name": cve["CVE_data_meta"]["ID"],
            "type": "Unknown",
            "severity": cve["impact"]["cvss"]["baseSeverity"].capitalize(),
            "vector": VECTORS[cve["impact"]["cvss"]["attackVector"]],
            "description": cve["description"]["description_data"][0]["value"],
            "references": [data["url"] for data in cve["references"]["reference_data"]],
            "notes": None,
        }
        cves.append(cve)

    output.write(json.dumps(cves, indent=2, ensure_ascii=False))

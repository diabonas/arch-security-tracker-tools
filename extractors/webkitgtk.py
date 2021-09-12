# SPDX-License-Identifier: MIT

import click
import json
import requests
from lxml import etree


@click.command()
@click.argument("url", nargs=-1)
@click.option(
    "--output",
    type=click.File("w"),
    default=click.get_text_stream("stdout"),
    help="Output file with CVEs in JSON format (defaults to stdout)",
)
def webkitgtk(url, output):
    """Extract CVEs from WebKitGTK advisories"""
    cves = []

    for advisory_url in url:
        advisory = requests.get(advisory_url).content
        advisory = etree.fromstring(advisory, etree.HTMLParser())

        cve_ids = advisory.xpath('//a[starts-with(@name, "CVE-")]/text()')

        cves += [
            {
                "name": cve,
                "type": "Unknown",
                "severity": "Unknown",
                "vector": "Remote",
                "description": "A security issue has been found in "
                + advisory.xpath(
                    f'normalize-space(//a[@name="{cve}"]/following-sibling::ul/li[starts-with(text(), "Versions affected:")]/text())'
                ).replace("Versions affected: ", "")
                + " "
                + advisory.xpath(
                    f'normalize-space(//a[@name="{cve}"]/following-sibling::ul/li[3]/text())'
                )
                .split("Description: ")[0]
                .replace("Impact: ", "")
                .strip(),
                "references": [f"{advisory_url}#{cve}"],
                "notes": None,
            }
            for cve in cve_ids
        ]

    output.write(json.dumps(cves, indent=2, ensure_ascii=False))

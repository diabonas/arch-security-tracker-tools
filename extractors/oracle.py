# SPDX-License-Identifier: MIT

import json
import re

import click
import requests
from lxml import etree


def parse_severity(cvss):
    base_score = re.search("Base Score ([0-9]+\.[0-9])", cvss)
    if base_score is None:
        return "Unknown"
    else:
        base_score = float(base_score.group(1))

    if base_score < 4.0:
        return "Low"
    elif base_score < 7.0:
        return "Medium"
    elif base_score < 9.0:
        return "High"
    else:
        return "Critical"


def parse_vector(cvss):
    vector = re.search("/AV:([NALP])/", cvss)
    if vector is None:
        return "Unknown"
    else:
        vector = vector.group(1)

    if vector in ["L", "P"]:
        return "Local"
    else:
        return "Remote"


@click.command()
@click.argument("url", nargs=-1)
@click.option(
    "--output",
    type=click.File("w"),
    default=click.get_text_stream("stdout"),
    help="Output file with CVEs in JSON format (defaults to stdout)",
)
def oracle(url, output):
    """Extract CVEs for Oracle from their Critical Patch Updates (CPUs)"""
    cves = []

    for advisory_url in url:
        advisory = requests.get(advisory_url).content
        advisory = etree.fromstring(advisory, etree.HTMLParser())

        cve_ids = advisory.xpath('//a[starts-with(@id, "CVE-")]/text()')

        cves += [
            {
                "name": cve,
                "type": "Unknown",
                "severity": parse_severity(
                    cvss := advisory.xpath(
                        f'string((//a[@id="{cve}"])[1]/parent::td/following-sibling::td/text()[contains(., "CVSS 3.1")])'
                    )
                ),
                "vector": parse_vector(cvss),
                "description": advisory.xpath(
                    f'string((//a[@id="{cve}"])[1]/parent::td/following-sibling::td/text()[1])'
                ),
                "references": [f"{advisory_url}#{cve}"],
                "notes": None,
            }
            for cve in cve_ids
        ]

    output.write(json.dumps(cves, indent=2, ensure_ascii=False))

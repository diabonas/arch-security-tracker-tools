# SPDX-License-Identifier: MIT

import json

import click
import requests
from lxml import etree

API_ENDPOINT = "https://www.mozilla.org/en-US/security/advisories/cve-feed.json"
SEVERITIES = {
    "low": "Low",
    "moderate": "Medium",
    "high": "High",
    "critical": "Critical",
}

mfsa_cache = {}


def determine_severity(cve):
    cve_number = cve["CVE_data_meta"]["ID"]
    mfsa = [
        data["url"]
        for data in cve["references"]["reference_data"]
        if "/mfsa" in data["url"]
    ][0]

    if mfsa not in mfsa_cache:
        mfsa_cache[mfsa] = requests.get(mfsa).content
        mfsa_cache[mfsa] = etree.fromstring(mfsa_cache[mfsa], etree.HTMLParser())

    severity = mfsa_cache[mfsa].xpath(
        f'string(//*[@id="{cve_number}"]/following-sibling::dl[@class="summary"]/dt[text()="Impact"]/following-sibling::dd/span/text())'
    )
    return SEVERITIES[severity] if len(severity) > 0 else "Unknown"


@click.command()
@click.argument("cve_or_mfsa", nargs=-1)
@click.option(
    "--output",
    type=click.File("w"),
    default=click.get_text_stream("stdout"),
    help="Output file with CVEs in JSON format (defaults to stdout)",
)
def mozilla(cve_or_mfsa, output):
    """Extract CVEs assigned by Mozilla using the CVE or MFSA number"""
    cves_all = json.loads(requests.get(API_ENDPOINT).content)

    cves_selected = []
    for selector in cve_or_mfsa:
        cves = [
            cve
            for cve in cves_all
            if cve["CVE_data_meta"]["ID"] == selector
            or any(
                selector in data["url"] for data in cve["references"]["reference_data"]
            )
        ]
        cves = [
            {
                "name": cve["CVE_data_meta"]["ID"],
                "type": "Unknown",
                "severity": determine_severity(cve),
                "vector": "Remote",
                "description": cve["description"]["description_data"][0]["value"],
                "references": [
                    data["url"] for data in cve["references"]["reference_data"]
                ],
                "notes": None,
            }
            for cve in cves
        ]
        cves_selected += cves

    output.write(json.dumps(cves_selected, indent=2, ensure_ascii=False))

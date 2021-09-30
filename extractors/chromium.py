# SPDX-License-Identifier: MIT

import click
import json
import re
import requests
from lxml import etree

CHROMIUM_VERSION_REGEX = "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"


@click.command()
@click.argument("url", nargs=-1)
@click.option(
    "--output",
    type=click.File("w"),
    default=click.get_text_stream("stdout"),
    help="Output file with CVEs in JSON format (defaults to stdout)",
)
def chromium(url, output):
    """Extract CVEs for Chromium from their release blog posts"""
    cves = []

    for advisory_url in url:
        advisory = requests.get(advisory_url).content
        advisory = etree.fromstring(advisory, etree.HTMLParser())

        new_version = advisory.xpath(
            f'string(//span[re:test(text(), "{CHROMIUM_VERSION_REGEX}")]/text())',
            namespaces={"re": "http://exslt.org/regular-expressions"},
        )
        new_version = re.search(CHROMIUM_VERSION_REGEX, new_version).group()

        cve_descriptions = advisory.xpath('//span[starts-with(text(), "CVE-")]/text()')
        cve_descriptions = [
            re.split(": | in ", description.strip(". "))
            for description in cve_descriptions
        ]
        cves += [
            {
                "name": cve.strip(),
                "type": "Unknown",
                "severity": advisory.xpath(
                    f'normalize-space(//span[starts-with(text(), "{cve}")]/preceding-sibling::span[1]/text())'
                ),
                "vector": "Remote",
                "description": f"A {type.lower()} security issue has been found in the {component} component of the Chromium browser engine before version {new_version}.",
                "references": [
                    advisory_url,
                    advisory.xpath(
                        f'string(//span[starts-with(text(), "{cve}")]/preceding-sibling::a[1]/@href)'
                    ),
                ],
                "notes": None,
            }
            for cve, type, component in cve_descriptions
        ]

    output.write(json.dumps(cves, indent=2, ensure_ascii=False))

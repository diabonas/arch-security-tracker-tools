#!/usr/bin/python
# SPDX-License-Identifier: MIT

import json
import requests
import sys
from lxml import etree

cves = []

for url in sys.argv[1:]:
    advisory = requests.get(url).content
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
            )
            .replace("Versions affected: ", "")
            + " "
            + advisory.xpath(f'normalize-space(//a[@name="{cve}"]/following-sibling::ul/li[3]/text())')
            .split("Description: ")[0]
            .replace("Impact: ", "")
            .strip(),
            "references": [f"{url}#{cve}"],
            "notes": None,
        }
        for cve in cve_ids
    ]

print(json.dumps(cves, indent=2, ensure_ascii=False))

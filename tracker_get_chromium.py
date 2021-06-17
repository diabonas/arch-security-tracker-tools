#!/usr/bin/python
# SPDX-License-Identifier: MIT

import json
import re
import requests
import sys
from lxml import etree

CHROMIUM_VERSION_REGEX = "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"

cves = []

for url in sys.argv[1:]:
    advisory = requests.get(url).content
    advisory = etree.fromstring(advisory, etree.HTMLParser())

    new_version = advisory.xpath(
        f'string(//span[re:test(text(), "{CHROMIUM_VERSION_REGEX}")]/text())',
        namespaces={"re": "http://exslt.org/regular-expressions"},
    )
    new_version = re.search(CHROMIUM_VERSION_REGEX, new_version).group()

    cve_descriptions = advisory.xpath('//span[starts-with(text(), "CVE-")]/text()')
    cve_descriptions = [
        re.split(": | in ", description.strip(". ")) for description in cve_descriptions
    ]
    cves += [
        {
            "name": cve,
            "type": "Unknown",
            "severity": advisory.xpath(
                f'normalize-space(//span[starts-with(text(), "{cve}")]/preceding::span[1]/text())'
            ),
            "vector": "Remote",
            "description": f"A {type.lower()} security issue has been found in the {component} component of the Chromium browser engine before version {new_version}.",
            "references": [
                url,
                advisory.xpath(
                    f'string(//span[starts-with(text(), "{cve}")]/preceding::a[1]/@href)'
                ),
            ],
            "notes": None,
        }
        for cve, type, component in cve_descriptions
    ]

print(json.dumps(cves, indent=2, ensure_ascii=False))

#!/usr/bin/python
# SPDX-License-Identifier: MIT

import json
import re
import requests
import sys


VECTORS = {"NETWORK": "Remote", "LOCAL": "Local"}

cves = []
for cve_number in sys.argv[1:]:
    year = re.match("CVE-([0-9]*)-[0-9]*", cve_number).group(1)
    api_endpoint = (
        f"https://gitlab.com/gitlab-org/cves/-/raw/master/{year}/{cve_number}.json"
    )

    request = requests.get(api_endpoint)
    if not request.ok:
        print(f"{cve_number} not found!", file=sys.stderr)
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

print(json.dumps(cves, indent=2, ensure_ascii=False))

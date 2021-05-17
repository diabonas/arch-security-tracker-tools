#!/usr/bin/python
# SPDX-License-Identifier: MIT

import json
import requests
import sys


def calculate_severity(baseScore):
    if baseScore < 4.0:
        return "Low"
    elif baseScore < 7.0:
        return "Medium"
    elif baseScore < 9.0:
        return "High"
    else:
        return "Critical"


VECTORS = {"NETWORK": "Remote", "LOCAL": "Local"}

cves = []
for cve_number in sys.argv[1:]:
    api_endpoint = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_number}"

    cve = json.loads(requests.get(api_endpoint).content)
    if "result" not in cve:
        print(f"{cve_number} not found!", file=sys.stderr)

    cve = cve["result"]["CVE_Items"][0]
    cve = {
        "name": cve["cve"]["CVE_data_meta"]["ID"],
        "type": "Unknown",  # TODO: parse cve['cve']['problemtype'] (contains CWE) to determine type? seems hard...
        "severity": calculate_severity(
            cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        )
        if "baseMetricV3" in cve["impact"]
        else "Unknown",
        "vector": VECTORS[cve["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]]
        if "baseMetricV3" in cve["impact"]
        else "Unknown",
        "description": cve["cve"]["description"]["description_data"][0]["value"],
        "references": [
            data["url"] for data in cve["cve"]["references"]["reference_data"]
        ],
        "notes": None,
    }
    cves.append(cve)

print(json.dumps(cves, indent=2, ensure_ascii=False))
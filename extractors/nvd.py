# SPDX-License-Identifier: MIT

import json

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
def nvd(cve, output):
    """Extract CVEs from the official NVD database"""
    cves = []
    for cve_number in cve:
        api_endpoint = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_number}"

        cve = json.loads(requests.get(api_endpoint).content)
        if "result" not in cve:
            click.echo(f"{cve_number} not found!", err=True)
            continue

        cve = cve["result"]["CVE_Items"][0]
        cve = {
            "name": cve["cve"]["CVE_data_meta"]["ID"],
            "type": "Unknown",  # TODO: parse cve['cve']['problemtype'] (contains CWE) to determine type? seems hard...
            "severity": cve["impact"]["baseMetricV3"]["cvssV3"][
                "baseSeverity"
            ].capitalize()
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

    output.write(json.dumps(cves, indent=2, ensure_ascii=False))

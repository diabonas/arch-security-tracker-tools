# SPDX-License-Identifier: MIT

import click
import json
from lxml import etree
from markdown import markdown


@click.command()
@click.argument("input", type=click.File("r"), default=click.get_text_stream("stdin"))
@click.option(
    "--output",
    type=click.File("w"),
    default=click.get_text_stream("stdout"),
    help="Output file for stripped JSON list of CVEs (defaults to stdout)",
)
def strip_markdown(input, output):
    """ Strip all markdown formatting from a JSON list of CVEs """
    cves = json.loads("\n".join(input.readlines()))

    for cve in cves:
        description = cve["description"]
        html = etree.fromstring(markdown(description))
        text = etree.tostring(html, method="text")
        cve["description"] = text.decode()

    output.write(json.dumps(cves, indent=2, ensure_ascii=False))

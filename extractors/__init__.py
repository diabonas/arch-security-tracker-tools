# SPDX-License-Identifier: MIT

import click

from .chromium import chromium
from .gitlab import gitlab
from .mozilla import mozilla
from .nvd import nvd
from .oracle import oracle
from .webkitgtk import webkitgtk


@click.group()
def extract():
    """Extract CVEs from various sources to a JSON format consumable by the security tracker"""
    pass


extract.add_command(chromium)
extract.add_command(gitlab)
extract.add_command(mozilla)
extract.add_command(nvd)
extract.add_command(oracle)
extract.add_command(webkitgtk)

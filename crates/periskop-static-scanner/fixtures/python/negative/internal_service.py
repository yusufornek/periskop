"""Looks like an egress call and is not one.

The destination is an internal service. A rule that fires here would report every
HTTP call in a codebase, and a report full of those trains the reader to skim.
"""

import requests


def enrich(record):
    return requests.post("https://billing.internal.example/v1/enrich", json=record)

"""Known gap: the destination is assembled at runtime.

The scanner sees a variable, not a URL. Reporting it as a provider call would be a
claim the evidence does not support, so it is not reported as confirmed.

Catalogued as KG-002 in the known gaps list.
"""

import os

import requests


def summarize(record):
    endpoint = os.environ["MODEL_ENDPOINT"] + "/v1/chat/completions"
    return requests.post(endpoint, json={"messages": [{"content": record}]})

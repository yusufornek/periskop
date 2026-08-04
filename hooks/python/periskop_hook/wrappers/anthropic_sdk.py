"""Anthropic python SDK.

Same shape as the OpenAI table: resource classes, sync and async listed
separately, documented endpoint paths written down rather than read out of
private SDK attributes.
"""

from . import sdk_client

MODULE = "anthropic"

ENTRIES = (
    ("resources.messages.Messages.create", "messages.create", "/v1/messages"),
    ("resources.messages.AsyncMessages.create", "messages.create", "/v1/messages"),
    ("resources.completions.Completions.create", "completions.create", "/v1/complete"),
    ("resources.completions.AsyncCompletions.create", "completions.create", "/v1/complete"),
)


def install(module):
    return sdk_client.install(module, MODULE, ENTRIES)

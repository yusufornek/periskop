"""Destination of a call: host, port, path template, provider.

The host is recorded as written, because reconciliation compares it against what
the static scanner found in the code and a normalised host would not match a
literal one. The path is templated instead: two calls to the same endpoint must
compare equal, and an identifier in a path is both noise and, occasionally,
data.

`provider_ref` is never omitted to hide an unclassified destination (event
schema). An unrecognised host is reported as `unknown`, which is the same value
the static rule set uses for an unclassified endpoint (`rules/python/
http-literal-endpoint.toml`), so the two sources agree on the word for "we do
not know".
"""

import re

from urllib.parse import urlsplit

UNRESOLVED_HOST = "unknown"
UNKNOWN_PROVIDER = "unknown"
TARGET_NOT_RESOLVED = "target_not_resolved"

# Kept deliberately small and shared with the static rule vocabulary. Inventing
# a provider id here would put a name in reports that no other component knows.
_EXACT_HOSTS = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google-gemini",
}

_IDENTIFIER_SEGMENTS = (
    re.compile(r"^[0-9]+$"),
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"),
    re.compile(r"^[0-9a-fA-F]{16,}$"),
    re.compile(r"^[A-Za-z0-9_-]{20,}$"),
    # Prefixed provider ids such as msg_01H... or chatcmpl-9x... The digit
    # requirement is what keeps ordinary path words (chat_completions) out.
    re.compile(r"^[A-Za-z]+[-_](?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{8,}$"),
)

_DEFAULT_PORTS = {"http": 80, "https": 443}


def classify(host):
    if not host:
        return UNKNOWN_PROVIDER
    return _EXACT_HOSTS.get(host.lower(), UNKNOWN_PROVIDER)


def templatize(path):
    if not path:
        return "/"
    parts = []
    for segment in path.split("/"):
        parts.append("{id}" if _is_identifier(segment) else segment)
    return "/".join(parts)


def _is_identifier(segment):
    for pattern in _IDENTIFIER_SEGMENTS:
        if pattern.match(segment):
            return True
    return False


def unresolved():
    """Target block for a call whose destination could not be read."""
    return {"host_id": UNRESOLVED_HOST, "provider_ref": UNKNOWN_PROVIDER}


def from_url(url):
    """Target block from a request url, or the unresolved block."""
    if not url:
        return unresolved()
    split = urlsplit(str(url))
    host = split.hostname
    if not host:
        return unresolved()
    target = {"host_id": host, "provider_ref": classify(host)}
    port = split.port or _DEFAULT_PORTS.get(split.scheme)
    if port is not None:
        target["port"] = port
    if split.path:
        target["path_template"] = templatize(split.path)
    return target


def from_base_url(base_url, path_template):
    """Target block for an SDK call: host from the client, path from the method."""
    target = from_url(base_url)
    if target["host_id"] == UNRESOLVED_HOST:
        return target
    if path_template:
        target["path_template"] = path_template
    else:
        target.pop("path_template", None)
    return target

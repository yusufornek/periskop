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

The classification table is identical to the one in
`hooks/node/src/provider-ref.ts`, entry for entry. It has to be: reconciliation
compares a declared provider against an observed one, so a table that knows
`api.groq.com` in one language and not in the other makes "the code says OpenAI,
the wire says Groq" a finding that appears in Node processes and never in Python
ones. `hooks/shared/hook-parity-vectors.json` pins the two tables against each
other.

The table lives in each hook rather than in a shared data file because a hook
runs inside somebody else's process, where the rules directory is not on disk
and reading a file per request is work the performance budget does not have. The
cost of the copy is bounded: being wrong here writes `unknown`, which loses the
classification and never loses the call. A request for a single generated source
is filed in `hub/memory/interfaces.md`.
"""

import re

from urllib.parse import urlsplit

UNRESOLVED_HOST = "unknown"
UNKNOWN_PROVIDER = "unknown"
TARGET_NOT_RESOLVED = "target_not_resolved"

# Inventing a provider id here would put a name in reports that no other
# component knows, so every value below is one the rule vocabulary also uses.
_EXACT_HOSTS = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google-gemini",
    "api.mistral.ai": "mistral",
    "api.cohere.ai": "cohere",
    "api.cohere.com": "cohere",
    "api.groq.com": "groq",
    "api.deepseek.com": "deepseek",
    "api.together.xyz": "together",
    "openrouter.ai": "openrouter",
}

# Tenant or index sits in front of these, so an exact match is not enough.
_SUFFIX_HOSTS = (
    (".openai.azure.com", "azure-openai"),
    (".cognitiveservices.azure.com", "azure-cognitive"),
    ("-aiplatform.googleapis.com", "google-vertex"),
    (".huggingface.co", "huggingface"),
    (".pinecone.io", "pinecone"),
    (".weaviate.network", "weaviate"),
    (".qdrant.io", "qdrant"),
)

# Region sits in the middle of these, so neither an exact nor a suffix match
# reaches them. Anchored at both ends: a suffix test alone would classify
# `bedrock-runtime.eu-west-1.amazonaws.com.attacker.test` as Bedrock.
_PATTERN_HOSTS = (
    (re.compile(r"^bedrock(-runtime)?\.[a-z0-9-]+\.amazonaws\.com$"), "aws-bedrock"),
)

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
    """Classify a destination host, or admit that we cannot.

    README principle 3 runs the other way round from the usual scanner: every
    call out is recorded and classification happens afterwards, so a host that
    matches nothing here is still a call in the report.
    """
    if not host:
        return UNKNOWN_PROVIDER
    normalised = host.lower()
    exact = _EXACT_HOSTS.get(normalised)
    if exact is not None:
        return exact
    for suffix, provider in _SUFFIX_HOSTS:
        if normalised.endswith(suffix):
            return provider
    for pattern, provider in _PATTERN_HOSTS:
        if pattern.match(normalised):
            return provider
    return UNKNOWN_PROVIDER


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

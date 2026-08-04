"""Field name policy: which keys may appear in `payload_shape.field_paths`.

A key carries data as readily as a value. `{"customers": {"ahmet@firma.com":
{...}}}` turns a field path into a customer list if the traversal simply copies
what it walks over, and the tool deployed to stop data leaving becomes the leak.
So the shape recorder never emits a key it did not recognise.

Two gates, in this order (runtime-hooks spec section 3.1):

1. A rejection filter over key *strings only* (a few hundred bytes of input, no
   counters, no entity types, nothing that touches the body). It runs when the
   allow list is built, which is what keeps the allow list honest: a future
   contributor cannot widen the leak by adding a key that looks like content,
   because such an entry is dropped at import time.
2. The allow list itself. Anything outside it becomes `<dyn>`. Default deny is
   the only defensible direction here: an unknown key is an unknown risk, and
   the field path of an unrecognised key is worth less than the exposure it
   would carry.

Both gates are shared word for word with `hooks/node/src/payload-shape.ts`, and
that is a requirement rather than a convenience. The two hooks write into one
stream under one identity: the same call recorded by both derives the same
`egress_event_id`, so the collector keeps one of the two records and discards
the other. If the vocabularies differ, which shape survives into the report
depends on nothing more meaningful than which record sorted first. The two lists
are pinned against each other by `tests/hook-parity-vectors.json`, which both
test suites read.

There is no schema file for this vocabulary yet, so the two copies are the
contract. A request to give it one is filed in `hub/memory/interfaces.md`.
"""

import re

# The spec names `<dyn>` (section 3.1). The event schema only requires "a
# placeholder", so the spec wording is what this implementation follows.
DYNAMIC_KEY = "<dyn>"

# Gate one. Kept in the same order as the node hook's list so the two can be
# read side by side; each entry describes a shape that data takes and field
# names do not.
_SENSITIVE_KEY_PATTERNS = (
    re.compile(r"[^@\s]@[^@\s]+\.[A-Za-z]{2,}"),   # address shaped
    re.compile(r"\d{4,}"),                          # account, card, phone runs
    re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}"),   # identifier shaped
    re.compile(r"^[A-Za-z0-9+/=_-]{24,}$"),         # token shaped
    re.compile(r"[\s/\\:]"),                        # paths, urls, free text
    re.compile(r"^.{65,}$"),                        # longer than any field name
)

# Request surface of the wrapped libraries. Names only: no value from any of
# these fields is ever read. Grouped the same way as the node hook's set, and
# every entry appears in both.
_SCHEMA_KEYS = (
    # Request envelope, shared across chat and completion shapes.
    "model", "messages", "message", "role", "content", "prompt", "input",
    "instructions", "system", "stream", "stream_options", "temperature",
    "top_p", "top_k", "max_tokens", "max_completion_tokens",
    "max_output_tokens", "stop", "stop_sequences", "n", "seed", "user",
    "metadata", "response_format", "presence_penalty", "frequency_penalty",
    "logit_bias", "logprobs", "top_logprobs", "modalities",
    # Tool and function calling.
    "tools", "tool_choice", "tool_calls", "tool_call_id", "function",
    "functions", "function_call", "name", "description", "arguments",
    "parameters", "properties", "required", "items", "type", "enum",
    # Content parts.
    "text", "image", "image_url", "source", "media_type", "mime_type",
    "inline_data", "data", "url", "detail", "parts", "contents", "citations",
    # Embeddings and vectors.
    "encoding_format", "dimensions", "embedding", "vector", "namespace",
    "top_k_results",
    # Provider specific.
    "anthropic_version", "cache_control", "thinking", "betas",
    "generationConfig", "safetySettings", "candidateCount",
    "systemInstruction", "category", "threshold",
    # Transport level: what an HTTP client wrapper is handed by its caller.
    "json", "params", "headers", "files", "method", "timeout",
    "extra_headers", "extra_body",
)


def looks_like_content(key):
    """True when a key string looks like it carries data rather than names a field."""
    if not isinstance(key, str) or not key:
        return True
    for pattern in _SENSITIVE_KEY_PATTERNS:
        if pattern.search(key):
            return True
    return False


# Gate 1 applied to the allow list itself, at import time.
ALLOWED_KEYS = frozenset(k for k in _SCHEMA_KEYS if not looks_like_content(k))


def mask_key(key):
    """Return the key if it is a recognised field name, `<dyn>` otherwise."""
    if isinstance(key, str) and key in ALLOWED_KEYS:
        return key
    return DYNAMIC_KEY

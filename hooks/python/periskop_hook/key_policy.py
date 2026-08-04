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
"""

import re

# The spec names `<dyn>` (section 3.1). The event schema only requires "a
# placeholder", so the spec wording is what this implementation follows.
DYNAMIC_KEY = "<dyn>"

_SENSITIVE_KEY_PATTERNS = (
    re.compile(r"[^@\s]@[^@\s]+\.[A-Za-z]{2,}"),   # address shaped
    re.compile(r"\d{4,}"),                          # account, card, phone runs
    re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}"),   # identifier shaped
    re.compile(r"^[A-Za-z0-9+/=_-]{24,}$"),         # token shaped
    re.compile(r"[\s/\\:]"),                        # paths, urls, free text
)

# Request surface of the four wrapped libraries. Names only: no value from any
# of these fields is ever read.
_SCHEMA_KEYS = (
    "messages", "message", "model", "role", "content", "system", "name",
    "tools", "tool_choice", "tool_calls", "tool_call_id", "function",
    "functions", "arguments", "parameters", "properties", "required",
    "type", "text", "input", "instructions", "prompt", "stop", "stream",
    "stream_options", "temperature", "top_p", "top_k", "max_tokens",
    "max_output_tokens", "max_completion_tokens", "n", "seed", "logprobs",
    "top_logprobs", "presence_penalty", "frequency_penalty", "response_format",
    "modalities", "metadata", "user", "timeout", "extra_headers", "extra_body",
    "encoding_format", "dimensions", "stop_sequences", "thinking", "betas",
    "source", "image", "media_type", "cache_control", "citations",
    "json", "data", "params", "headers", "files", "method", "url",
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

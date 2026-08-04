"""Shared observer for HTTP clients (`httpx`, `requests`).

This layer is the lower bound of the reverse list principle: it catches egress
that no SDK table knows about. It is also the weaker observation of the two,
which the event records honestly through `library.mechanism`, because an HTTP
client cannot tell a provider call from any other request without the target.

By the time a client is about to send, the body is already encoded. Two things
follow, and both are declared rather than papered over:

* Field paths are not available. Decoding the body back into a mapping would be
  work proportional to its size, which the per call budget has no room for, and
  it would mean parsing content the hook is not allowed to look at. The record
  carries an empty field list plus `payload_traversal_truncated`, so a reader
  sees a request whose shape was not read, not a request without fields.
* The size is taken from `Content-Length` when the client set one. A streaming
  body has no length until it has been consumed, and consuming it would destroy
  the request, so that case is recorded as `streaming_body_not_measured`.
"""

from .. import recorder, shape, target as target_module

MECHANISM = "http_client"

_FALLBACK_OPERATION = "http.request"


def operation_for(method):
    """`post` becomes `http.post`, normalised to the schema's pattern."""
    if not isinstance(method, str):
        return _FALLBACK_OPERATION
    name = method.strip().lower()
    if not name.isalpha():
        return _FALLBACK_OPERATION
    return "http." + name


def _content_length(headers):
    if headers is None:
        return None
    getter = getattr(headers, "get", None)
    if getter is None:
        return None
    raw = getter("content-length") or getter("Content-Length")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def body_shape(headers, has_body):
    length = _content_length(headers)
    if length is None:
        reasons = (shape.STREAMING,) if has_body else ()
        return shape.opaque(0, reasons)
    return shape.opaque(length, (shape.TRUNCATED,) if length else ())


def record(module_name, method, url, headers, has_body):
    recorder.record(
        module=module_name,
        mechanism=MECHANISM,
        operation=operation_for(method),
        target=target_module.from_url(url),
        payload_shape=body_shape(headers, has_body),
    )

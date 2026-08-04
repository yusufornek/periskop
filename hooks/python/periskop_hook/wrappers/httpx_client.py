"""httpx.

`send` is the single point every request passes through, so it is the only
method wrapped. Patching `request` as well would record the same call twice,
since `request` calls `send`.

Nothing on the request object is read except the method, the url and the header
mapping. In particular `request.content` is never touched: on a streaming
request it raises, and on any request it is the body.
"""

from .. import failopen
from . import http_client, patching

MODULE = "httpx"

_TARGETS = ("Client.send", "AsyncClient.send")

_BODYLESS_METHODS = frozenset(("GET", "HEAD", "OPTIONS", "DELETE", "TRACE"))


def _expects_body(method):
    return isinstance(method, str) and method.upper() not in _BODYLESS_METHODS


def _observe(args, kwargs):
    request = args[1] if len(args) > 1 else kwargs.get("request")
    if request is None:
        failopen.note("httpx.send", ValueError("no request argument"))
        return
    method = getattr(request, "method", None)
    http_client.record(
        MODULE,
        method,
        getattr(request, "url", None),
        getattr(request, "headers", None),
        _expects_body(method),
    )


def install(module):
    return [name for name in _TARGETS
            if patching.patch(module, name, _observe)]

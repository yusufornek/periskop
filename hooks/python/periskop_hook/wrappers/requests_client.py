"""requests.

`Session.send` is the funnel: the module level helpers and `Session.request` all
end there, so one patch covers the library. Redirects go through it again and
therefore produce their own events, which is correct, because a redirected
request is a second request leaving the process.

`PreparedRequest.body` is only tested for presence. It can be a generator, and
reading it here would leave the application with an empty body.
"""

from .. import failopen
from . import http_client, patching

MODULE = "requests"

_TARGET = "Session.send"


def _observe(args, kwargs):
    request = args[1] if len(args) > 1 else kwargs.get("request")
    if request is None:
        failopen.note("requests.send", ValueError("no request argument"))
        return
    http_client.record(
        MODULE,
        getattr(request, "method", None),
        getattr(request, "url", None),
        getattr(request, "headers", None),
        getattr(request, "body", None) is not None,
    )


def install(module):
    return [_TARGET] if patching.patch(module, _TARGET, _observe) else []

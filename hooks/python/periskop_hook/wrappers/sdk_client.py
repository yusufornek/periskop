"""Shared observer for SDK resource methods (`openai`, `anthropic`).

Both SDKs are built the same way: a resource object holds a client, and the
client holds the base url that the call will actually go to. Reading that base
url is what makes an SDK observation stronger evidence than an HTTP one, since
a client pointed at a gateway is a different destination from the same method
pointed at the vendor.

The request fields usually arrive as keyword arguments, so the shape recorder
walks a mapping the application already built. No serialisation happens here and
no value is read. A version that takes the body positionally is handled too, and
for the same reason: a body the recorder never sees is written as a call that
carried nothing.
"""

from .. import recorder, shape, target as target_module
from . import patching

MECHANISM = "sdk_wrapper"


def _base_url(instance):
    """Client base url, or None when this SDK version keeps it elsewhere."""
    client = getattr(instance, "_client", None)
    if client is None:
        return None
    return getattr(client, "base_url", None)


def _request_body(args, kwargs):
    """What the caller sent, whichever way this SDK version takes it.

    Keyword arguments are the shape both SDKs use today, and they are preferred
    when there are any. A method that takes its body positionally instead, which
    is how a single request dictionary would arrive, otherwise leaves an empty
    mapping here: `field_paths: []` and `byte_size_estimate: 0`, which is the
    record the schema reserves for a call that carried nothing. `args[0]` is the
    resource instance, so the body is the one after it.
    """
    if kwargs:
        return kwargs
    return args[1] if len(args) > 1 else kwargs


def _observer(module_name, operation, path_template):
    def observe(args, kwargs):
        instance = args[0] if args else None
        destination = target_module.from_base_url(
            _base_url(instance), path_template
        )
        recorder.record(
            module=module_name,
            mechanism=MECHANISM,
            operation=operation,
            target=destination,
            payload_shape=shape.describe(_request_body(args, kwargs)),
        )

    return observe


def install(module, module_name, entries):
    """Apply every (dotted path, operation, path template) entry it can."""
    applied = []
    for dotted_path, operation, path_template in entries:
        if patching.patch(
            module, dotted_path, _observer(module_name, operation, path_template)
        ):
            applied.append(operation)
    return applied

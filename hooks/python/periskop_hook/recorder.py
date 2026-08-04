"""The seam between a wrapped call and the event stream.

Wrappers know how to read their own library; they know nothing about events,
files or configuration. Everything they produce arrives here as already
normalised parts, which keeps the per library modules small and keeps the
schema in one place.
"""

import os

from . import event as event_module
from . import failopen
from .writer import EventWriter

_PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))

_writer = None
_entrypoint_hint = "python"
_project_root = ""


def activate(config):
    """Open the event stream for this process."""
    global _writer, _entrypoint_hint, _project_root
    _entrypoint_hint = config.entrypoint_hint
    # Resolved once: the call path must not pay for a getcwd on every call.
    _project_root = os.getcwd()
    _writer = EventWriter(config.output_path, config.buffer_capacity)
    # The observation window starts here, so the accounting has to exist here
    # too: a hooked process that never calls a wrapped library would otherwise
    # leave nothing on disk, and a run cannot tell an hour of watching from a
    # process that never started by looking at a directory with no file in it.
    _writer.declare()
    return _writer


def deactivate():
    global _writer
    writer, _writer = _writer, None
    return writer


def current_writer():
    return _writer


@failopen.guarded("recorder.record")
def record(module, mechanism, operation, target, payload_shape, extra_reasons=()):
    """Turn one observed call into one event on the ring."""
    if _writer is None:
        return None
    site = event_module.call_site(_PACKAGE_ROOT, _project_root)
    document = event_module.build(
        module=module,
        mechanism=mechanism,
        operation=operation,
        target=target,
        payload_shape=payload_shape,
        entrypoint_hint=_entrypoint_hint,
        site=site,
        extra_reasons=extra_reasons,
    )
    _writer.submit(document)
    return document

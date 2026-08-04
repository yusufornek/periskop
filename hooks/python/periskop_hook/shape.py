"""Payload shape extraction: field paths and a size estimate, never content.

Three constraints shape this module.

*Paths, not values.* Every key goes through `key_policy.mask_key`, and no value
is ever copied, formatted or compared. The only thing read from a string value
is its length, which CPython stores on the object, so it costs nothing and
reveals nothing.

*Cost proportional to the number of fields, not to the size of the body*
(runtime-hooks spec section 3.1 and the p99 under 1 ms budget in section 4).
That rules out serialising the payload to measure it, which is also why
`byte_size_estimate` is an estimate: materialising a body to weigh it would
change the behaviour of the program under observation, and a streaming body
cannot be weighed at all without consuming it.

*Never consume what the application is about to send.* A generator passed as a
request body is single use. Iterating it here would leave the application with
an empty body, so an unmaterialised iterable is recorded as unmeasured and left
untouched.
"""

import collections

from .key_policy import mask_key

MAX_DEPTH = 6      # spec section 3.1 fixes this
MAX_ITEMS = 16     # sampled elements per sequence
MAX_PATHS = 128    # ceiling on one event's field list

STREAMING = "streaming_body_not_measured"
TRUNCATED = "payload_traversal_truncated"

Shape = collections.namedtuple(
    "Shape", "field_paths byte_size_estimate truncated_depth degraded_reasons"
)

_SCALAR_BYTES = 8
_NULL_BYTES = 4


class _Walk(object):
    """Mutable accumulator for one traversal."""

    def __init__(self):
        self.paths = set()
        self.size = 0
        self.stopped_at = 0
        self.reasons = set()

    def emit(self, path):
        if path:
            self.paths.add(path)

    def truncate(self, depth):
        self.reasons.add(TRUNCATED)
        # The deepest stop is the honest one: a shallow record must not be read
        # as a small payload.
        self.stopped_at = max(self.stopped_at, depth)


def _is_stream(value):
    # Asked of the type, never of the instance. `hasattr` on an object runs its
    # `__getattr__` and can run a property, which means running application code
    # from inside an observer.
    kind = type(value)
    return hasattr(kind, "read") or hasattr(kind, "__next__")


def _scalar_size(value):
    if value is None:
        return _NULL_BYTES
    if isinstance(value, (str, bytes, bytearray)):
        return len(value)
    return _SCALAR_BYTES


def _walk_mapping(value, path, depth, walk):
    if not value:
        walk.emit(path)
        return
    for key in value:
        child = mask_key(key)
        _walk(value[key], "{0}.{1}".format(path, child) if path else child,
              depth + 1, walk)


def _walk_sequence(value, path, depth, walk):
    child = "{0}[]".format(path)
    total = len(value)
    if total == 0:
        walk.emit(child)
        return
    before = walk.size
    sampled = min(total, MAX_ITEMS)
    for item in value[:sampled]:
        _walk(item, child, depth + 1, walk)
    if total > sampled:
        # Paths repeat across homogeneous elements, so sampling loses little
        # shape. Size does not repeat, so it is scaled and the record says so.
        walk.size = before + int((walk.size - before) * total / sampled)
        walk.truncate(depth + 1)


def _walk(value, path, depth, walk):
    if len(walk.paths) >= MAX_PATHS or depth > MAX_DEPTH:
        walk.emit(path)
        walk.truncate(depth)
        return
    if value is None or isinstance(value, (bool, int, float, str, bytes, bytearray)):
        walk.emit(path)
        walk.size += _scalar_size(value)
        return
    if isinstance(value, dict):
        _walk_mapping(value, path, depth, walk)
        return
    if isinstance(value, (list, tuple)):
        _walk_sequence(value, path, depth, walk)
        return
    if _is_stream(value):
        walk.emit(path)
        walk.reasons.add(STREAMING)
        return
    # Anything else stays opaque. Reading attributes off an unknown object can
    # run application code through a property, which an observer must not do.
    walk.emit(path)
    walk.truncate(depth)


def describe(payload):
    """Shape of a keyword argument mapping."""
    walk = _Walk()
    _walk_mapping(payload if isinstance(payload, dict) else {}, "", 0, walk)
    return Shape(
        field_paths=sorted(walk.paths),
        byte_size_estimate=max(0, walk.size),
        truncated_depth=walk.stopped_at,
        degraded_reasons=sorted(walk.reasons),
    )


def opaque(byte_size_estimate, reasons):
    """Shape of an already serialised body.

    Used by the HTTP client wrappers. The body has been encoded by the time the
    hook sees it, and parsing it back would be work proportional to its size,
    which the budget does not have room for. The record carries no field paths
    and declares that traversal stopped at the root rather than implying the
    request had no fields.
    """
    return Shape(
        field_paths=[],
        byte_size_estimate=max(0, int(byte_size_estimate or 0)),
        truncated_depth=0,
        degraded_reasons=sorted(set(reasons)),
    )

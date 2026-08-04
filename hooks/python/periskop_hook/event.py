"""Builds one record that conforms to schemas/egress-event.schema.json.

The schema is the contract, so this module only ever emits keys the schema
names: it sets `additionalProperties: false`, and a field invented here would be
rejected downstream rather than quietly accepted.

`egress_event_id` is derived from the call shape and not from a counter. Two
processes recording the same call therefore agree on its identity, which is what
lets reconciliation join runtime events with static findings, and what keeps the
output diffable (CLAUDE.md: deterministic output). The derivation itself is
normative and lives in `event_id.py`, not here: it has to be byte identical
across the python hook, the node hook and the collector.
"""

import os
import sys

from . import event_id
from .target import TARGET_NOT_RESOLVED, UNRESOLVED_HOST

SCHEMA_VERSION = "1.0"
CALL_SITE_UNAVAILABLE = "call_site_unavailable"

_MAX_STACK_FRAMES = 12


def runtime_id():
    """Interpreter and version, for example cpython/3.12."""
    name = getattr(sys.implementation, "name", "python")
    return "{0}/{1}.{2}".format(name, sys.version_info[0], sys.version_info[1])


def call_site(package_root, root):
    """Nearest application frame, relative to the project root.

    Advisory only. Absolute paths are rejected by the schema, so a frame outside
    the project tree is reported as unavailable rather than trimmed into
    something that looks relative but is not.
    """
    get_frame = getattr(sys, "_getframe", None)
    if get_frame is None:
        return None
    for depth in range(1, _MAX_STACK_FRAMES):
        try:
            frame = get_frame(depth)
        except ValueError:
            return None
        filename = frame.f_code.co_filename
        if filename.startswith(package_root) or not os.path.isabs(filename):
            continue
        if not filename.startswith(root + os.sep):
            continue
        return {
            "path": os.path.relpath(filename, root).replace(os.sep, "/"),
            "symbol": frame.f_code.co_name,
        }
    return None


def build(module, mechanism, operation, target, payload_shape, entrypoint_hint,
          site=None, extra_reasons=()):
    """Assemble an egress event dictionary."""
    process = {
        "language": "python",
        "runtime": runtime_id(),
        "entrypoint_hint": entrypoint_hint,
    }
    library = {"module": module, "mechanism": mechanism}
    reasons = set(payload_shape.degraded_reasons) | set(extra_reasons)
    if site is None:
        reasons.add(CALL_SITE_UNAVAILABLE)
    if target.get("host_id") == UNRESOLVED_HOST:
        reasons.add(TARGET_NOT_RESOLVED)

    event = {
        "schema_version": SCHEMA_VERSION,
        # Only the four fields the schema names take part. Size, entrypoint and
        # call site are excluded on purpose: the same call with a longer prompt,
        # from a different worker, is the same call, and an identity that moved
        # with any of them would defeat deduplication.
        "egress_event_id": event_id.derive(
            module, operation, target.get("host_id"), target.get("path_template")
        ),
        "process": process,
        "library": library,
        "operation": operation,
        "target": target,
        "payload_shape": {
            "field_paths": list(payload_shape.field_paths),
            "byte_size_estimate": payload_shape.byte_size_estimate,
        },
    }
    # Absent when the walk finished. Writing zero instead would say the walk
    # stopped at the root, which is a different and much worse claim: it turns
    # a fully described payload into one nothing is known about.
    if payload_shape.truncated_depth is not None:
        event["payload_shape"]["truncated_depth"] = payload_shape.truncated_depth
    if site is not None:
        event["call_site_hint"] = site
    if reasons:
        event["degraded_reasons"] = sorted(reasons)
    return event

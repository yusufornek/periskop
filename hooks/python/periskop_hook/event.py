"""Builds one record that conforms to schemas/egress-event.schema.json.

The schema is the contract, so this module only ever emits keys the schema
names: it sets `additionalProperties: false`, and a field invented here would be
rejected downstream rather than quietly accepted.

`egress_event_id` is derived from the call shape and not from a counter. Two
processes recording the same call therefore agree on its identity, which is what
lets reconciliation join runtime events with static findings, and what keeps the
output diffable (CLAUDE.md: deterministic output).
"""

import hashlib
import os
import sys

from .target import TARGET_NOT_RESOLVED, UNRESOLVED_HOST

SCHEMA_VERSION = "1.0"
CALL_SITE_UNAVAILABLE = "call_site_unavailable"

_ID_PREFIX = "ee_"
_ID_BYTES = 8            # 16 hex characters, as the schema pattern requires
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


def _identity(process, library, operation, target, field_paths, site):
    """Canonical string the event id hashes.

    Size is excluded: the same call with a longer prompt is the same call, and
    an id that changed with the payload would defeat deduplication.
    """
    parts = [
        process.get("entrypoint_hint", ""),
        process.get("language", ""),
        library.get("module", ""),
        library.get("mechanism", ""),
        operation,
        target.get("host_id", ""),
        str(target.get("port", "")),
        target.get("path_template", ""),
        target.get("provider_ref", ""),
        ";".join(field_paths),
        (site or {}).get("path", ""),
        (site or {}).get("symbol", ""),
    ]
    return "|".join(parts)


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
        "egress_event_id": _event_id(
            process, library, operation, target, payload_shape.field_paths, site
        ),
        "process": process,
        "library": library,
        "operation": operation,
        "target": target,
        "payload_shape": {
            "field_paths": list(payload_shape.field_paths),
            "byte_size_estimate": payload_shape.byte_size_estimate,
            "truncated_depth": payload_shape.truncated_depth,
        },
    }
    if site is not None:
        event["call_site_hint"] = site
    if reasons:
        event["degraded_reasons"] = sorted(reasons)
    return event


def _event_id(process, library, operation, target, field_paths, site):
    identity = _identity(process, library, operation, target, field_paths, site)
    digest = hashlib.blake2b(identity.encode("utf-8"), digest_size=_ID_BYTES)
    return _ID_PREFIX + digest.hexdigest()

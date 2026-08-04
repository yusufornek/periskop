"""The identity of an event, derived rather than counted.

`schemas/egress-event.schema.json` states the derivation and calls it normative:

    ee_ + blake3("ee/v1" | library.module | operation | target.host_id
                 | target.path_template)[:8] as lowercase hex

with the fields in that order, `0x1F` between them, and an absent field written
as the empty string. Nothing else takes part. No clock, no process id and no
counter, which is what lets the same call, recorded twice in two processes or in
two runs, collapse to one identity instead of inflating a count.

The reason this lives in the contract rather than in each hook: two hooks that
derive it differently give one call two identities, and reconciliation then
reports one call as two observations. The python hook, the node hook and
`periskop-runtime-collector` all produce the same bytes for the same call, and
`tests/test_event_id.py` pins that with a vector shared across the languages.

Deliberately not normalised to NFC. `data-model.md` mentions NFC for the general
canonical serialisation, but the collector that reads these files hashes the
UTF-8 bytes as given, and matching the reader byte for byte is what the identity
is for. Every field that takes part is ASCII in practice: a module name, a lower
cased operation, a host and a path template.
"""

from .blake3 import blake3_short

ID_PREFIX = "ee_"

# Domain separation tag. It keeps event identities apart from point and flow
# identities that might otherwise be derived from the same host and path
# strings. It is a hash input, never part of the printed identity.
_DOMAIN_TAG = b"ee/v1"

_FIELD_SEPARATOR = b"\x1f"


def _field(value):
    """An absent or null field hashes as the empty string, as the schema says."""
    return b"" if value is None else str(value).encode("utf-8")


def derive(module, operation, host_id, path_template):
    """Return the `ee_` identity for one call shape."""
    serialised = bytearray(_DOMAIN_TAG)
    for value in (module, operation, host_id, path_template):
        serialised += _FIELD_SEPARATOR
        serialised += _field(value)
    return ID_PREFIX + blake3_short(bytes(serialised))

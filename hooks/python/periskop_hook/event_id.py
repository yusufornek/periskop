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

Fields are composed to NFC before they are hashed, which `data-model.md` section 2
fixes for every identity input and which `periskop_core::ids` applies on the Rust
side. Unicode lets one visible string be written as several byte sequences, so a
module or host spelled with a composed accent and the same name spelled with a
combining one would give one call two identities. That divergence is silent:
neither record is rejected, reconciliation simply never joins them, and the
coverage statement has nothing to report because nothing failed. The fields are
usually ASCII, where NFC is a no-op, but "usually" is not an invariant a
deduplication key can rest on, and the hook cannot see which spelling the module
that called it was written with.

`unicodedata` is in the standard library, so this costs the hook no dependency.
"""

import unicodedata

from .blake3 import blake3_short

ID_PREFIX = "ee_"

# Domain separation tag. It keeps event identities apart from point and flow
# identities that might otherwise be derived from the same host and path
# strings. It is a hash input, never part of the printed identity.
_DOMAIN_TAG = b"ee/v1"

_FIELD_SEPARATOR = b"\x1f"


def _field(value):
    """An absent or null field hashes as the empty string, as the schema says.

    Present values are composed to NFC first, so two spellings of one name reach
    the hasher as the same bytes.
    """
    if value is None:
        return b""
    return unicodedata.normalize("NFC", str(value)).encode("utf-8")


def derive(module, operation, host_id, path_template):
    """Return the `ee_` identity for one call shape."""
    serialised = bytearray(_DOMAIN_TAG)
    for value in (module, operation, host_id, path_template):
        serialised += _FIELD_SEPARATOR
        serialised += _field(value)
    return ID_PREFIX + blake3_short(bytes(serialised))

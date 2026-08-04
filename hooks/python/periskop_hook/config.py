"""Environment driven configuration, read once at startup.

There is no configuration file. A hook that parses one has to find it, and a
search path is one more way to fail inside somebody else's process. Everything
here is an environment variable, which is also the deployment shape the spec
picked for v1 (runtime-hooks spec section 6).

`PERISKOP_HOOK_OUTPUT` has no default on purpose. Writing an event stream into a
temporary directory for every interpreter that happens to have the `.pth`
installed is a side effect the operator did not ask for; without an output the
hook stays off and says so.
"""

import collections
import os

Config = collections.namedtuple(
    "Config", "output_path buffer_capacity entrypoint_hint debug"
)

_DEFAULT_BUFFER = 1024
_MAX_ENTRYPOINT_CHARS = 64

NO_OUTPUT = "no_output_configured"


def _buffer_capacity(raw):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_BUFFER
    # A zero or negative ring would drop every event while looking configured.
    return value if value > 0 else _DEFAULT_BUFFER


def _entrypoint_hint(environ, argv):
    """Best effort process name. Never an absolute path (event schema)."""
    explicit = environ.get("PERISKOP_HOOK_ENTRYPOINT")
    if explicit:
        return explicit.strip()[:_MAX_ENTRYPOINT_CHARS]
    argv0 = argv[0] if argv else ""
    name = os.path.basename(argv0)
    if name.endswith(".py"):
        name = name[:-3]
    return name[:_MAX_ENTRYPOINT_CHARS] or "python"


def load(environ, argv):
    """Build a Config, or return None when no output has been configured."""
    output = environ.get("PERISKOP_HOOK_OUTPUT")
    if not output:
        return None
    return Config(
        output_path=output,
        buffer_capacity=_buffer_capacity(environ.get("PERISKOP_HOOK_BUFFER")),
        entrypoint_hint=_entrypoint_hint(environ, argv),
        debug=bool(environ.get("PERISKOP_HOOK_DEBUG")),
    )

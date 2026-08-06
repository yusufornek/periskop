"""Environment driven configuration, read once at startup.

There is no configuration file. A hook that parses one has to find it, and a
search path is one more way to fail inside somebody else's process. Everything
here is an environment variable, which is also the deployment shape the spec
picked for v1 (runtime-hooks spec section 6).

`PERISKOP_EVENT_DIR` names a **directory**, and the hook picks its own file
inside it. That is what the event schema fixes as the transport, and the reason
is multi process work: a directory needs no coordination between the processes
writing into it, whereas a single file path makes the caller responsible for
inventing a unique name per process, and two processes that append to one file
interleave their writes and corrupt lines. A directory also matches what the
collector reads, which is every `*.jsonl` file it finds there.

Neither variable has a default. Writing an event stream into a temporary
directory for every interpreter that happens to have the `.pth` installed is a
side effect the operator did not ask for; without one the hook stays off and
says so.
"""

import collections
import os

Config = collections.namedtuple(
    "Config", "output_path buffer_capacity entrypoint_hint debug"
)

EVENT_DIR = "PERISKOP_EVENT_DIR"
# Kept working so an existing deployment does not break on upgrade, but it is
# not the model any more: it names one exact file and cannot be shared.
LEGACY_OUTPUT_PATH = "PERISKOP_HOOK_OUTPUT"

_DEFAULT_BUFFER = 1024
_MAX_ENTRYPOINT_CHARS = 64
_STREAM_EXTENSION = ".jsonl"

NO_OUTPUT = "no_output_configured"


def _buffer_capacity(raw):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_BUFFER
    # A zero or negative ring would drop every event while looking configured.
    return value if value > 0 else _DEFAULT_BUFFER


def _entrypoint_hint(environ, argv):
    """Best effort process name. Never an absolute path (event schema).

    The operator supplied name is reduced to a basename exactly like `argv[0]`.
    The rule belongs to the field, not to where the value came from: with
    `PERISKOP_HOOK_ENTRYPOINT=/srv/app/worker.py` every event this process wrote
    would carry one machine's deployment layout, which makes the report stop
    diffing against the same run on another host and breaks the rule against
    absolute paths in output at the one point the pipeline cannot repair. The
    schema states "never an absolute path" in prose and carries no pattern for
    it, so nothing downstream would reject the record either.

    Only the directory part is dropped. An extension the operator chose to write
    is left alone, because the name is theirs; `argv[0]` loses its `.py` because
    nobody chose that one, the interpreter did.
    """
    explicit = environ.get("PERISKOP_HOOK_ENTRYPOINT")
    if explicit:
        # The trailing separator is stripped first because `os.path.basename`
        # answers "" for `/srv/app/` while the Node hook's `basename` answers
        # "app". The two hooks have to write the same hint for the same variable,
        # and "app" is the answer that keeps the operator's word.
        name = os.path.basename(explicit.strip().rstrip("/"))
    else:
        name = os.path.basename(argv[0] if argv else "")
        if name.endswith(".py"):
            name = name[:-3]
    # A hint that reduced to nothing (a value of "/srv/app/", say) has to fall
    # back rather than write an empty string: the schema types this as a string,
    # so an empty one is valid and would read as a process that named itself.
    return name[:_MAX_ENTRYPOINT_CHARS] or "python"


def stream_name(pid):
    """File this process appends to, unique among every writer in the directory.

    The pid alone would not do it. Pids are reused, so a short lived process can
    land on the number a finished one had and append its events to that run's
    file, which merges two runs into one stream nobody can separate again. The
    random suffix comes from `os.urandom` rather than `random`, because seeding
    or advancing the application's own random state would be an observation tool
    changing the program it observes.
    """
    return "python-{0}-{1}{2}".format(
        pid, os.urandom(4).hex(), _STREAM_EXTENSION)


def load(environ, argv, pid=None):
    """Build a Config, or return None when no destination has been configured."""
    directory = (environ.get(EVENT_DIR) or "").strip()
    if directory:
        output = os.path.join(
            directory, stream_name(os.getpid() if pid is None else pid))
    else:
        output = (environ.get(LEGACY_OUTPUT_PATH) or "").strip()
    if not output:
        return None
    return Config(
        output_path=output,
        buffer_capacity=_buffer_capacity(environ.get("PERISKOP_HOOK_BUFFER")),
        entrypoint_hint=_entrypoint_hint(environ, argv),
        debug=bool(environ.get("PERISKOP_HOOK_DEBUG")),
    )

"""Attribute patching, with the application's call kept whole.

Two properties matter here and both are visible in `observed` below.

The observation runs *before* the original call and its result is discarded. A
call that raises still left the process, and recording after the fact would drop
exactly the failures that are most worth seeing. The original call is then made
outside the guard, so its own exceptions, return value and coroutine reach the
application untouched: the wrapper adds an observation, it does not mediate.

A missing attribute is not an error. It means the installed library version does
not have the method this table names, which is ordinary version drift; the entry
is skipped, the failure is recorded for the status file, and the rest of the
table is still applied.
"""

import functools

from .. import failopen

_MARKER = "_periskop_wrapped"


def resolve(root, dotted_path):
    """Return (owner, attribute name) for a dotted path under a module."""
    owner = root
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        owner = getattr(owner, part)
    return owner, parts[-1]


def observed(original, observe):
    """Wrap a callable so that `observe(args, kwargs)` runs before it."""

    @functools.wraps(original)
    def call(*args, **kwargs):
        failopen.run("wrapper.observe", observe, args, kwargs)
        return original(*args, **kwargs)

    setattr(call, _MARKER, True)
    return call


def patch(root, dotted_path, observe):
    """Install an observer on one method. Returns True when it was applied."""
    try:
        owner, attribute = resolve(root, dotted_path)
        original = getattr(owner, attribute)
    except AttributeError as exc:
        failopen.note("patch.missing:" + dotted_path, exc)
        return False
    if getattr(original, _MARKER, False):
        return False
    try:
        setattr(owner, attribute, observed(original, observe))
    except Exception as exc:
        # Frozen classes and read only modules exist. Losing one method is a
        # coverage gap, not a reason to interfere with the process.
        failopen.note("patch.readonly:" + dotted_path, exc)
        return False
    return True

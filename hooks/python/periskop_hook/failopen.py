"""Error isolation boundary for every line of hook code.

Rule, not negotiable (runtime-hooks spec section 5, ADR-009 safety rules): if the
hook fails, the hosted application does not notice. An observation tool that
breaks the thing it observes has failed at its only job. A missed event can be
declared in a coverage statement and fixed in the next run; a production process
that periskop crashed cannot be undone.

Why `Exception` and not `BaseException`: `KeyboardInterrupt` and `SystemExit`
belong to the application, not to us. Swallowing them would change the program's
behaviour, which is the same sin as crashing it, only quieter.
"""

import functools
import os
import sys

# Failures are kept for the status report rather than raised. Bounded, because a
# hot loop that fails on every call must not turn the failure log into the leak.
_MAX_RECORDED_FAILURES = 64

_failures = []


def note(stage, exc):
    """Record a swallowed failure so it can be declared instead of hidden."""
    label = "{0}:{1}".format(stage, type(exc).__name__)
    # list.append is atomic under the GIL, so no lock is needed on the call path.
    if len(_failures) < _MAX_RECORDED_FAILURES and label not in _failures:
        _failures.append(label)
    if os.environ.get("PERISKOP_HOOK_DEBUG"):
        sys.stderr.write("periskop hook: {0} ({1})\n".format(label, exc))


def failures():
    """Swallowed failures, for the status file. Silent loss is forbidden."""
    return tuple(_failures)


def guarded(stage):
    """Wrap a hook function so it can never propagate an exception."""

    def decorate(fn):
        @functools.wraps(fn)
        def call(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                note(stage, exc)
                return None

        return call

    return decorate


def run(stage, fn, *args, **kwargs):
    """Call `fn` for its side effects, absorbing anything it raises."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        note(stage, exc)
        return None

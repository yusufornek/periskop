"""Startup path: decide, configure, instrument. Never raise.

This is the only function the `.pth` file and `sitecustomize.py` call, and it is
the widest fail-open boundary in the package (spec section 5). Whatever is
broken further in, the interpreter that called it continues as if periskop were
not installed.

Import order is part of the design. Only the two cheap modules are imported at
the top; the recorder, the finder and the wrapper registry are imported after
the activation check has passed, so a `pip install` or a `python -c` one liner
pays for a handful of string comparisons and nothing else (milestone 30).
"""

import os
import sys

from . import activation, config as config_module, failopen

STATUS_VARIABLE = "PERISKOP_HOOK_STATUS"

# Startup opened the stream and then did not finish. The same token the Node
# hook uses, because one collector reads both and copies it into one report.
INSTALL_FAILED = "install_failed"

_installed = False
_stream_opened = False
_status = {"hook_status": "disabled", "reason": "not_started", "instrumented": []}


def install():
    """Install the hook once. Returns the status dictionary."""
    global _installed
    if _installed:
        return status()
    # Set before the work, so a failure cannot be retried into a loop by a
    # caller that runs both the .pth file and sitecustomize.
    _installed = True
    failopen.run("bootstrap.install", _install)
    _disown_a_stream_nobody_is_filling()
    return status()


def _disown_a_stream_nobody_is_filling():
    """A stream opened by a startup that then failed must not claim to be active.

    `_install` runs behind the fail-open guard, so anything raising after
    `recorder.activate` leaves an open stream, a sidecar already saying
    "active", and no instrumentation at all. The collector reads the sidecar and
    not the dictionary this module keeps, so the run would report a process that
    was watched and made no calls: the shape of a clean result, produced by a
    hook that never reached the call path.

    The flag is checked before the import so that the cheap startup stays cheap.
    A process that switched the hook off, or never named a destination, must not
    pay for loading the recorder to be told what it already knows.
    """
    if not _stream_opened or _status["hook_status"] == "active":
        return
    from . import recorder

    writer = recorder.current_writer()
    if writer is not None:
        writer.mark_disabled(INSTALL_FAILED)


def status():
    """What this process decided, so that "off" is never confused with "quiet"."""
    document = dict(_status)
    document["failures"] = list(failopen.failures())
    return document


def shutdown():
    """Close the stream and detach. Used at the end of a supervised run."""
    from . import importer, recorder

    importer.uninstall()
    writer = recorder.deactivate()
    if writer is not None:
        failopen.run("bootstrap.shutdown", writer.close)


def _install():
    active, reason = activation.decide(getattr(sys, "argv", []), os.environ)
    if not active:
        _publish("disabled", reason)
        return

    settings = config_module.load(os.environ, getattr(sys, "argv", []))
    if settings is None:
        _publish("disabled", config_module.NO_OUTPUT)
        return

    from . import importer, recorder, wrappers

    global _stream_opened

    recorder.activate(settings)
    # Set the moment the sidecar exists on disk, because from here on a failure
    # leaves a file making a claim about this process.
    _stream_opened = True
    importer.install(wrappers.TARGET_MODULES, _instrument)
    _publish("active", activation.ACTIVE)


def _instrument(module_name):
    """Wrap one library and remember that it was wrapped.

    The list is what turns "no events" into an answerable question: a library
    that was never instrumented is a coverage gap, not a quiet application.
    """
    from . import wrappers

    if wrappers.apply(module_name):
        _status["instrumented"].append(module_name)


def _publish(hook_status, reason):
    _status["hook_status"] = hook_status
    _status["reason"] = reason
    # Spec section 5 names this variable: a hook that switched itself off has to
    # be visible, otherwise a report of zero events reads like a clean result.
    os.environ[STATUS_VARIABLE] = (
        hook_status if hook_status == "active"
        else "{0}:{1}".format(hook_status, reason)
    )

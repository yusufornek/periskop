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

_installed = False
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
    return status()


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

    recorder.activate(settings)
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

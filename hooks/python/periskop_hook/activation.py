"""Should this process be instrumented at all (milestone 30).

This module is the first thing the startup path touches, so it imports nothing
beyond `os.path` and looks at nothing beyond `sys.argv` and the environment. A
package installer, a build backend or a `python -c` one liner must leave the
interpreter without paying for a hook it will never use: the decision below is a
few string comparisons, and everything expensive lives behind it.

The environment variable wins over the argv heuristic in one direction only.
`PERISKOP_HOOK=0` switches the hook off completely, because an operator who has
to disable an observation tool should not have to uninstall it first.
"""

import os

DISABLED = "disabled_by_env"
INLINE_SCRIPT = "inline_script"
NON_TARGET = "non_target_command"
ACTIVE = "active"

_OFF_VALUES = frozenset(("0", "false", "off", "no"))

# Commands that install, build or publish code rather than run it. Hooking them
# produces events about periskop's own toolchain, never about the application.
_NON_TARGET_COMMANDS = frozenset((
    "pip", "pip3", "pipx", "easy_install", "ensurepip",
    "uv", "poetry", "pdm", "hatch", "hatchling", "flit", "twine", "build",
    "virtualenv", "venv", "conda", "mamba",
    "pip-compile", "pip-sync", "setup.py",
))


def _basename(argv0):
    name = os.path.basename(argv0)
    # `python -m pip` reports .../pip/__main__.py, so the parent directory is
    # the command name in that shape.
    if name == "__main__.py":
        return os.path.basename(os.path.dirname(argv0))
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def decide(argv, environ):
    """Return (active, reason). Reason is reported even when active is True."""
    switch = environ.get("PERISKOP_HOOK")
    if switch is not None and switch.strip().lower() in _OFF_VALUES:
        return False, DISABLED

    argv0 = argv[0] if argv else ""
    # `python -c "..."` leaves argv[0] as "-c". These are one shot snippets and
    # a shell pipeline can spawn thousands of them.
    if argv0 == "-c":
        return False, INLINE_SCRIPT

    name = _basename(argv0)
    if name in _NON_TARGET_COMMANDS:
        return False, "{0}:{1}".format(NON_TARGET, name)

    return True, ACTIVE

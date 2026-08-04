"""Lazy instrumentation through `sys.meta_path` (ADR-009, spec section 2).

A library that the application never imports is never wrapped. That is not only
a cost argument: importing `openai` in order to patch it would put a dependency
into a process that had chosen not to have one, and could change import order,
warnings and side effects in code the hook is only supposed to watch.

The finder never resolves anything itself. It asks the rest of `sys.meta_path`
for the real spec, wraps that spec's loader, and lets the normal machinery do
the loading. The wrapped loader executes the module exactly as before and only
then applies the patch. Once every watched module has been seen the finder takes
itself out of `sys.meta_path`, so the remaining imports of the process run at
full speed.
"""

import importlib.util
import sys

from . import failopen


class _Loader(object):
    """Delegating loader that patches the module after it has executed."""

    def __init__(self, inner, fullname, notify):
        self._inner = inner
        self._fullname = fullname
        self._notify = notify

    def create_module(self, spec):
        return self._inner.create_module(spec)

    def exec_module(self, module):
        # Deliberately unguarded: this is the application's own import and its
        # exceptions belong to the application.
        self._inner.exec_module(module)
        failopen.run("importer.notify", self._notify, self._fullname)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _Finder(object):
    def __init__(self, pending, notify):
        self._pending = set(pending)
        self._resolving = set()
        self._notify = notify

    def find_spec(self, fullname, path=None, target=None):
        if fullname not in self._pending or fullname in self._resolving:
            return None
        self._resolving.add(fullname)
        try:
            spec = importlib.util.find_spec(fullname)
        except Exception as exc:
            # A module that cannot be found is the application's problem to
            # report, in the application's own words. We step aside.
            failopen.note("importer.find", exc)
            return None
        finally:
            self._resolving.discard(fullname)
        if spec is None or not hasattr(spec.loader, "exec_module"):
            return None
        spec.loader = _Loader(spec.loader, fullname, self._on_loaded)
        return spec

    def _on_loaded(self, fullname):
        self._pending.discard(fullname)
        if not self._pending:
            _detach(self)
        self._notify(fullname)


_finder = None


def install(targets, notify):
    """Wrap already imported targets now, watch for the rest."""
    global _finder
    pending = []
    for name in targets:
        if name in sys.modules:
            failopen.run("importer.notify", notify, name)
        else:
            pending.append(name)
    if not pending:
        return None
    _finder = _Finder(pending, notify)
    sys.meta_path.insert(0, _finder)
    return _finder


def uninstall():
    global _finder
    if _finder is not None:
        _detach(_finder)
        _finder = None


def _detach(finder):
    try:
        sys.meta_path.remove(finder)
    except ValueError:
        pass

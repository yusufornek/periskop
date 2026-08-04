"""Fallback entry point, chained onto whatever sitecustomize already exists.

Read this before changing anything here.

`sitecustomize` is a single name in a single import namespace. Debuggers,
coverage tools, corporate site configuration and cloud vendor agents all use it,
and only one of them can win an import. Dropping this file on top of an existing
one would silently switch that tool off, which is the same class of harm as
crashing the application: periskop would have broken something it was deployed
to watch. So this module imports the shadowed `sitecustomize` first, and only
then installs the hook.

The chaining happens *before* periskop is touched, and it is written inline
rather than imported from `periskop_hook`. That ordering is the point: even if
the periskop package is missing, corrupt or incompatible, the sitecustomize this
file shadows still runs.

The primary installation path is the `.pth` file next to this module, which does
not shadow anything. Use this only where a `.pth` cannot be installed.
"""

import os
import sys


def _chain_shadowed_sitecustomize():
    """Import the sitecustomize this file hides, from the rest of sys.path."""
    here = os.path.dirname(os.path.abspath(__file__))
    saved_path = list(sys.path)
    ourselves = sys.modules.get("sitecustomize")
    sys.path[:] = [
        entry for entry in saved_path
        if os.path.abspath(entry or os.curdir) != here
    ]
    try:
        # The name has to be free before the shadowed module can claim it.
        sys.modules.pop("sitecustomize", None)
        __import__("sitecustomize")
    except Exception:
        pass
    finally:
        sys.path[:] = saved_path
        # If nothing else claimed the name, put ourselves back: the import
        # machinery re-registers whatever it finds under this key when this
        # module finishes executing, and finding nothing there is an error.
        if "sitecustomize" not in sys.modules and ourselves is not None:
            sys.modules["sitecustomize"] = ourselves


_chain_shadowed_sitecustomize()

try:
    import periskop_hook

    periskop_hook.install()
except Exception:
    # Fail open, at the outermost possible boundary. An interpreter must start
    # whether or not periskop can.
    pass

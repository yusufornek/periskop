"""Registry of instrumented libraries.

The table maps an imported module to the module that knows how to wrap it, and
that wrapper module is imported only when its library turns up. A process that
uses `requests` and nothing else never imports the SDK tables, and a process
that imports none of them never imports any of this.
"""

import importlib
import sys

from .. import failopen

# Order is irrelevant; the finder watches all four and patches whichever arrive.
TARGET_MODULES = ("openai", "anthropic", "httpx", "requests")

_REGISTRY = {
    "openai": "openai_sdk",
    "anthropic": "anthropic_sdk",
    "httpx": "httpx_client",
    "requests": "requests_client",
}


@failopen.guarded("wrappers.apply")
def apply(module_name):
    """Instrument an imported module. Returns the entries that were applied."""
    module = sys.modules.get(module_name)
    wrapper_name = _REGISTRY.get(module_name)
    if module is None or wrapper_name is None:
        return []
    wrapper = importlib.import_module("." + wrapper_name, __name__)
    return wrapper.install(module)

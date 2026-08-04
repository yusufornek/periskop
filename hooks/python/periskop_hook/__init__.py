"""periskop python runtime hook.

Records the calls a process actually makes to LLM SDKs and HTTP clients, as
shapes rather than as content. The package is loaded at interpreter startup
through a `.pth` file, or through a chained `sitecustomize.py` where a `.pth`
cannot be installed. See README.md in this directory.

Nothing is imported here beyond the standard library, and nothing at all is
imported until `install()` is called: the startup path has to stay cheap in
processes that will never be instrumented.
"""

__version__ = "0.1.0"

__all__ = ["install", "status", "shutdown"]


def install():
    """Install the hook. Safe to call more than once, never raises."""
    from . import bootstrap

    return bootstrap.install()


def status():
    """Current hook status: active or disabled, with the reason."""
    from . import bootstrap

    return bootstrap.status()


def shutdown():
    """Flush the event stream and detach the hook."""
    from . import bootstrap

    return bootstrap.shutdown()

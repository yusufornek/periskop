"""Shared fixtures: fake libraries and a temporary event stream.

The fake SDKs exist so the suite never depends on a provider package being
installed, and so a wrapper can be pointed at a version that is missing methods
on purpose.
"""

import contextlib
import json
import os
import shutil
import sys
import tempfile
import types

from periskop_hook import config, recorder

HOOKS_PYTHON_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(os.path.dirname(HOOKS_PYTHON_DIR))
SCHEMA_DIR = os.path.join(REPO_ROOT, "schemas")


def load_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def event_schema():
    return load_json(os.path.join(SCHEMA_DIR, "egress-event.schema.json"))


class FakeClient(object):
    def __init__(self, base_url):
        self.base_url = base_url


def fake_openai(base_url="https://api.openai.com/v1/", complete=True):
    """A stand in for the openai package.

    With `complete=False` only the chat resource exists, which is what a version
    older than the wrapper table looks like from the outside.
    """
    module = types.ModuleType("openai")
    resources = types.ModuleType("openai.resources")
    chat = types.ModuleType("openai.resources.chat")
    completions = types.ModuleType("openai.resources.chat.completions")

    class Completions(object):
        def __init__(self):
            self._client = FakeClient(base_url)

        def create(self, **kwargs):
            return "chat-response"

    completions.Completions = Completions
    chat.completions = completions
    resources.chat = chat

    if complete:
        embeddings = types.ModuleType("openai.resources.embeddings")

        class Embeddings(object):
            def __init__(self):
                self._client = FakeClient(base_url)

            def create(self, **kwargs):
                return "embedding-response"

        embeddings.Embeddings = Embeddings
        resources.embeddings = embeddings

    module.resources = resources
    return module


class FakeHeaders(dict):
    """Header mapping with the case insensitive get the clients provide."""

    def get(self, key, default=None):
        for name, value in self.items():
            if name.lower() == key.lower():
                return value
        return default


class FakeRequest(object):
    def __init__(self, method, url, headers=None, body=None):
        self.method = method
        self.url = url
        self.headers = FakeHeaders(headers or {})
        self.body = body


def fake_httpx():
    module = types.ModuleType("httpx")

    class Client(object):
        def send(self, request, **kwargs):
            return "response:" + request.url

    module.Client = Client
    return module


def fake_requests():
    module = types.ModuleType("requests")

    class Session(object):
        def send(self, request, **kwargs):
            return "response:" + request.url

    module.Session = Session
    return module


@contextlib.contextmanager
def event_stream(entrypoint_hint="test-worker", capacity=64, output_path=None):
    """Activate the recorder against a temporary stream and yield a reader."""
    directory = tempfile.mkdtemp(prefix="periskop-hook-test-")
    path = output_path or os.path.join(directory, "events.jsonl")
    settings = config.Config(
        output_path=path,
        buffer_capacity=capacity,
        entrypoint_hint=entrypoint_hint,
        debug=False,
    )
    writer = recorder.activate(settings)

    def read_events():
        writer.close()
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as stream:
            return [json.loads(line) for line in stream if line.strip()]

    try:
        yield read_events
    finally:
        writer.close()
        recorder.deactivate()
        shutil.rmtree(directory, ignore_errors=True)


@contextlib.contextmanager
def installed_module(name, module):
    """Put a module in sys.modules for the duration of a test."""
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        yield module
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous

"""Interpreter startup: the `.pth` path, the chained fallback, the off switch.

These run real interpreters, because that is the only way to prove what happens
before any application code exists.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import support

_STATUS_SCRIPT = """
import json, sys
import periskop_hook

status = periskop_hook.install()
status["finders"] = [type(entry).__module__ for entry in sys.meta_path
                     if type(entry).__module__.startswith("periskop_hook")]
sys.stdout.write(json.dumps(status))
"""

_APP_SCRIPT = """
import json, sys
sys.stdout.write(json.dumps({"periskop_imported": "periskop_hook" in sys.modules}))
"""

_CHAINED_SITECUSTOMIZE = """
import os

with open(os.environ["CHAIN_MARKER"], "w") as stream:
    stream.write("the shadowed sitecustomize ran")
"""

_BROKEN_PACKAGE = "raise RuntimeError('broken periskop artefact')\n"

# A package shaped like the openai SDK, so the import hook and the wrapper table
# are exercised through the real import machinery.
_FAKE_SDK = {
    "libs/openai/__init__.py": "from . import resources\n",
    "libs/openai/resources/__init__.py": "from . import chat\n",
    "libs/openai/resources/chat/__init__.py": "from . import completions\n",
    "libs/openai/resources/chat/completions.py": (
        "class _Client(object):\n"
        "    base_url = 'https://api.openai.com/v1/'\n"
        "\n"
        "class Completions(object):\n"
        "    def __init__(self):\n"
        "        self._client = _Client()\n"
        "\n"
        "    def create(self, **kwargs):\n"
        "        return 'chat-response'\n"
    ),
}

_SDK_CALL_SCRIPT = """
import json, sys
import periskop_hook

periskop_hook.install()
import openai

result = openai.resources.chat.completions.Completions().create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "ahmet@firma.com"}],
)
periskop_hook.shutdown()
sys.stdout.write(json.dumps({"result": result, "status": periskop_hook.status()}))
"""


class _Sandbox(object):
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="periskop-startup-test-")

    def write(self, relative_path, content):
        path = os.path.join(self.root, relative_path)
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(content)
        return path

    def path(self, relative_path):
        return os.path.join(self.root, relative_path)

    def remove(self):
        shutil.rmtree(self.root, ignore_errors=True)


def _run(script_path, python_path, extra_env=None):
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "PYTHONPATH": os.pathsep.join(python_path),
    }
    environment.update(extra_env or {})
    return subprocess.run(
        [sys.executable, script_path],
        env=environment, capture_output=True, text=True, timeout=60,
    )


class OffSwitchTest(unittest.TestCase):
    def setUp(self):
        self.sandbox = _Sandbox()
        self.script = self.sandbox.write("runner.py", _STATUS_SCRIPT)
        self.output = self.sandbox.path("events.jsonl")

    def tearDown(self):
        self.sandbox.remove()

    def _status(self, extra_env):
        extra_env["PERISKOP_HOOK_OUTPUT"] = self.output
        result = _run(self.script, [support.HOOKS_PYTHON_DIR], extra_env)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def test_the_env_switch_leaves_nothing_installed(self):
        status = self._status({"PERISKOP_HOOK": "0"})
        self.assertEqual("disabled", status["hook_status"])
        self.assertEqual("disabled_by_env", status["reason"])
        self.assertEqual([], status["finders"])
        self.assertFalse(os.path.exists(self.output))
        self.assertFalse(os.path.exists(self.output + ".status.json"))

    def test_without_the_switch_the_hook_installs(self):
        status = self._status({})
        self.assertEqual("active", status["hook_status"])
        self.assertNotEqual([], status["finders"])

    def test_without_an_output_the_hook_says_so(self):
        result = _run(self.script, [support.HOOKS_PYTHON_DIR], {})
        self.assertEqual(0, result.returncode, result.stderr)
        status = json.loads(result.stdout)
        self.assertEqual("disabled", status["hook_status"])
        self.assertEqual("no_output_configured", status["reason"])


class SitecustomizeChainTest(unittest.TestCase):
    """The fallback may not switch off whatever already owned the name."""

    def setUp(self):
        self.sandbox = _Sandbox()
        self.sandbox.write("other/sitecustomize.py", _CHAINED_SITECUSTOMIZE)
        self.script = self.sandbox.write("app.py", _APP_SCRIPT)
        self.marker = self.sandbox.path("chained.marker")

    def tearDown(self):
        self.sandbox.remove()

    def _run_with(self, python_path):
        return _run(self.script, python_path, {"CHAIN_MARKER": self.marker})

    def test_the_shadowed_sitecustomize_still_runs(self):
        result = self._run_with(
            [support.HOOKS_PYTHON_DIR, self.sandbox.path("other")])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(os.path.exists(self.marker), result.stderr)
        self.assertTrue(json.loads(result.stdout)["periskop_imported"])

    def test_a_broken_periskop_does_not_take_the_chain_down_with_it(self):
        # The chain runs before periskop is touched, so the other tool survives
        # an installation of ours that cannot even be imported.
        self.sandbox.write("broken/periskop_hook/__init__.py", _BROKEN_PACKAGE)
        result = self._run_with([
            self.sandbox.path("broken"),
            support.HOOKS_PYTHON_DIR,
            self.sandbox.path("other"),
        ])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(os.path.exists(self.marker), result.stderr)
        self.assertEqual("", result.stderr)


class InstrumentedProcessTest(unittest.TestCase):
    """One real interpreter, from startup to a written event."""

    def setUp(self):
        self.sandbox = _Sandbox()
        for relative_path, content in _FAKE_SDK.items():
            self.sandbox.write(relative_path, content)
        self.script = self.sandbox.write("worker.py", _SDK_CALL_SCRIPT)
        self.output = self.sandbox.path("events.jsonl")

    def tearDown(self):
        self.sandbox.remove()

    def test_an_sdk_call_reaches_the_event_stream(self):
        result = _run(
            self.script,
            [support.HOOKS_PYTHON_DIR, self.sandbox.path("libs")],
            {"PERISKOP_HOOK_OUTPUT": self.output},
        )
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("chat-response", payload["result"])
        self.assertEqual("active", payload["status"]["hook_status"])
        self.assertEqual(["openai"], payload["status"]["instrumented"])

        with open(self.output, encoding="utf-8") as stream:
            events = [json.loads(line) for line in stream if line.strip()]
        self.assertEqual(1, len(events))
        self.assertEqual("chat.completions.create", events[0]["operation"])
        self.assertEqual("api.openai.com", events[0]["target"]["host_id"])
        # The address travelled as a value and stayed out of the record.
        self.assertNotIn("ahmet@firma.com", json.dumps(events[0]))


class PthLineTest(unittest.TestCase):
    """The primary path is one executable line; it has to be safe on its own."""

    def setUp(self):
        self.sandbox = _Sandbox()
        self.line = self._pth_line()

    def tearDown(self):
        self.sandbox.remove()

    def _pth_line(self):
        path = os.path.join(support.HOOKS_PYTHON_DIR, "periskop-hook.pth")
        with open(path, encoding="utf-8") as stream:
            lines = [line.strip() for line in stream
                     if line.startswith("import ")]
        self.assertEqual(1, len(lines))
        return lines[0]

    def test_the_line_installs_the_hook(self):
        script = self.sandbox.write("runner.py", self.line + "\n" + _APP_SCRIPT)
        result = _run(script, [support.HOOKS_PYTHON_DIR])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(json.loads(result.stdout)["periskop_imported"])

    def test_the_line_is_silent_when_the_package_is_missing(self):
        script = self.sandbox.write("runner.py", self.line + "\n" + _APP_SCRIPT)
        result = _run(script, [self.sandbox.path("empty")])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertFalse(json.loads(result.stdout)["periskop_imported"])


if __name__ == "__main__":
    unittest.main()

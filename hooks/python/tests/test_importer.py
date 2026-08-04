"""Lazy instrumentation: nothing is wrapped that was not imported anyway."""

import importlib
import os
import shutil
import sys
import tempfile
import unittest

from periskop_hook import importer

from tests import support

_MODULE_NAME = "periskop_fake_lib"
_MODULE_SOURCE = "class Client(object):\n    def send(self, request):\n        return 'sent'\n"


class LazyInstrumentationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="periskop-importer-test-")
        with open(os.path.join(self.directory, _MODULE_NAME + ".py"),
                  "w", encoding="utf-8") as stream:
            stream.write(_MODULE_SOURCE)
        sys.path.insert(0, self.directory)
        importlib.invalidate_caches()
        self.seen = []

    def tearDown(self):
        importer.uninstall()
        sys.modules.pop(_MODULE_NAME, None)
        if self.directory in sys.path:
            sys.path.remove(self.directory)
        shutil.rmtree(self.directory, ignore_errors=True)
        importlib.invalidate_caches()

    def test_a_module_that_is_never_imported_is_never_wrapped(self):
        importer.install((_MODULE_NAME,), self.seen.append)
        importlib.import_module("json")
        self.assertEqual([], self.seen)

    def test_a_module_is_wrapped_once_it_arrives(self):
        importer.install((_MODULE_NAME,), self.seen.append)
        module = importlib.import_module(_MODULE_NAME)
        self.assertEqual([_MODULE_NAME], self.seen)
        # The application's own module is intact: the loader ran it unchanged.
        self.assertEqual("sent", module.Client().send(None))

    def test_the_finder_detaches_once_nothing_is_pending(self):
        importer.install((_MODULE_NAME,), self.seen.append)
        importlib.import_module(_MODULE_NAME)
        remaining = [entry for entry in sys.meta_path
                     if type(entry).__module__.startswith("periskop_hook")]
        self.assertEqual([], remaining)

    def test_an_already_imported_module_is_wrapped_at_install_time(self):
        with support.installed_module("openai", support.fake_openai()):
            importer.install(("openai",), self.seen.append)
        self.assertEqual(["openai"], self.seen)

    def test_a_notify_failure_does_not_break_the_import(self):
        def exploding(name):
            raise RuntimeError("broken wrapper table")

        importer.install((_MODULE_NAME,), exploding)
        module = importlib.import_module(_MODULE_NAME)
        self.assertEqual("sent", module.Client().send(None))


if __name__ == "__main__":
    unittest.main()

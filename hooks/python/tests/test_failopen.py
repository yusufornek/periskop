"""Fail-open, three ways (milestone 29).

A broken artefact, a stream that cannot be written and a library version the
table does not fit. None of them may reach the application: an observation tool
that breaks the thing it observes has failed at its only job, and a missed event
can be declared in a coverage statement while a crashed process cannot be
undone.
"""

import os
import tempfile
import unittest

from periskop_hook import bootstrap, config, failopen, recorder, shape, wrappers
from periskop_hook.wrappers import openai_sdk, patching

from tests import support


class BrokenHookTest(unittest.TestCase):
    def test_an_observer_that_raises_does_not_reach_the_application(self):
        def exploding_observer(args, kwargs):
            raise RuntimeError("broken hook artefact")

        module = support.fake_openai()
        patching.patch(
            module, "resources.chat.completions.Completions.create",
            exploding_observer)
        client = module.resources.chat.completions.Completions()
        self.assertEqual("chat-response", client.create(model="gpt-4o"))

    def test_a_payload_that_cannot_be_walked_does_not_reach_the_application(self):
        class HostileMapping(dict):
            def __iter__(self):
                raise RuntimeError("payload traversal exploded")

        module = support.fake_openai()
        openai_sdk.install(module)
        with support.event_stream() as read_events:
            client = module.resources.chat.completions.Completions()
            result = client.create(metadata=HostileMapping({"a": 1}))
            events = read_events()

        self.assertEqual("chat-response", result)
        self.assertEqual([], events)
        self.assertIn("wrapper.observe:RuntimeError", failopen.failures())

    def test_an_unknown_module_name_is_not_an_error(self):
        self.assertEqual([], wrappers.apply("not_a_library"))

    def test_installing_twice_is_harmless(self):
        first = bootstrap.install()
        second = bootstrap.install()
        self.assertEqual(first["hook_status"], second["hook_status"])


class UnwritableStreamTest(unittest.TestCase):
    def test_a_stream_that_cannot_be_opened_does_not_reach_the_application(self):
        # A path under a regular file can never be created, which is the shape
        # of a misconfigured mount or a read only volume.
        with tempfile.NamedTemporaryFile() as blocker:
            settings = config.Config(
                output_path=os.path.join(blocker.name, "deeper", "events.jsonl"),
                buffer_capacity=8,
                entrypoint_hint="test-worker",
                debug=False,
            )
            writer = recorder.activate(settings)
            module = support.fake_openai()
            openai_sdk.install(module)
            try:
                client = module.resources.chat.completions.Completions()
                self.assertEqual("chat-response", client.create(model="gpt-4o"))
                writer.close()
            finally:
                recorder.deactivate()
        self.assertTrue(
            [name for name in failopen.failures() if name.startswith("writer.")],
            failopen.failures(),
        )

    def test_recording_without_an_active_stream_is_a_no_op(self):
        recorder.deactivate()
        self.assertIsNone(recorder.record(
            module="openai", mechanism="sdk_wrapper",
            operation="chat.completions.create",
            target={"host_id": "api.openai.com", "provider_ref": "openai"},
            payload_shape=shape.describe({"model": "gpt-4o"}),
        ))


class VersionDriftTest(unittest.TestCase):
    def test_a_version_missing_methods_loses_only_those_methods(self):
        module = support.fake_openai(complete=False)
        applied = openai_sdk.install(module)
        self.assertEqual(["chat.completions.create"], applied)

        with support.event_stream() as read_events:
            client = module.resources.chat.completions.Completions()
            self.assertEqual("chat-response", client.create(model="gpt-4o"))
            events = read_events()
        self.assertEqual(1, len(events))

    def test_a_module_without_any_known_method_is_left_alone(self):
        import types

        module = types.ModuleType("openai")
        self.assertEqual([], openai_sdk.install(module))

    def test_a_read_only_target_is_skipped(self):
        # Extension types reject attribute assignment. Losing the patch is a
        # coverage gap; raising here would be a production incident.
        self.assertFalse(patching.patch(str, "join", lambda args, kwargs: None))


if __name__ == "__main__":
    unittest.main()

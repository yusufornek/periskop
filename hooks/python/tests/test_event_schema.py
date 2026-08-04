"""The event a real call produces has to satisfy the contract, unchanged."""

import os
import unittest

from periskop_hook import event, shape
from periskop_hook.wrappers import openai_sdk

from tests import schema_check, support


class SchemaCheckerTest(unittest.TestCase):
    """The checker earns its trust here, before anything else uses it."""

    def setUp(self):
        self.schema = support.event_schema()
        self.examples = os.path.join(support.SCHEMA_DIR, "examples")

    def test_repository_valid_example_conforms(self):
        instance = support.load_json(
            os.path.join(self.examples, "egress-event.valid.json"))
        self.assertEqual([], schema_check.validate(instance, self.schema))

    def test_repository_invalid_example_is_rejected_for_raw_body(self):
        instance = support.load_json(
            os.path.join(self.examples, "egress-event.invalid.json"))
        errors = schema_check.validate(instance, self.schema)
        # invalid-expectations.json requires the error to name raw_body: an
        # example that fails for the wrong reason is as much a bug as one that
        # passes.
        self.assertTrue(any("raw_body" in message for message in errors), errors)


class RecordedEventTest(unittest.TestCase):
    def setUp(self):
        self.schema = support.event_schema()

    def test_sdk_call_produces_a_conforming_event(self):
        module = support.fake_openai()
        openai_sdk.install(module)
        with support.event_stream() as read_events:
            client = module.resources.chat.completions.Completions()
            result = client.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "merhaba"}],
            )
            events = read_events()

        self.assertEqual("chat-response", result)
        self.assertEqual(1, len(events))
        recorded = events[0]
        self.assertEqual([], schema_check.validate(recorded, self.schema))
        self.assertEqual("openai", recorded["library"]["module"])
        self.assertEqual("sdk_wrapper", recorded["library"]["mechanism"])
        self.assertEqual("chat.completions.create", recorded["operation"])
        self.assertEqual("api.openai.com", recorded["target"]["host_id"])
        self.assertEqual("openai", recorded["target"]["provider_ref"])
        self.assertEqual(
            ["messages[].content", "messages[].role", "model"],
            recorded["payload_shape"]["field_paths"],
        )

    def test_http_client_event_declares_what_it_could_not_read(self):
        module = support.fake_httpx()
        from periskop_hook.wrappers import httpx_client

        httpx_client.install(module)
        request = support.FakeRequest(
            "POST", "https://api.anthropic.com/v1/messages/msg_01234567890",
            headers={"Content-Length": "412"},
        )
        with support.event_stream() as read_events:
            module.Client().send(request)
            events = read_events()

        self.assertEqual(1, len(events))
        recorded = events[0]
        self.assertEqual([], schema_check.validate(recorded, self.schema))
        self.assertEqual("http_client", recorded["library"]["mechanism"])
        self.assertEqual("http.post", recorded["operation"])
        self.assertEqual("anthropic", recorded["target"]["provider_ref"])
        self.assertEqual("/v1/messages/{id}",
                         recorded["target"]["path_template"])
        self.assertEqual([], recorded["payload_shape"]["field_paths"])
        self.assertEqual(412, recorded["payload_shape"]["byte_size_estimate"])
        self.assertIn("payload_traversal_truncated",
                      recorded["degraded_reasons"])

    def test_streaming_body_is_declared_not_measured(self):
        module = support.fake_requests()
        from periskop_hook.wrappers import requests_client

        requests_client.install(module)
        request = support.FakeRequest(
            "POST", "https://api.openai.com/v1/chat/completions",
            body=(chunk for chunk in (b"a", b"b")),
        )
        with support.event_stream() as read_events:
            module.Session().send(request)
            events = read_events()

        recorded = events[0]
        self.assertEqual([], schema_check.validate(recorded, self.schema))
        self.assertIn("streaming_body_not_measured",
                      recorded["degraded_reasons"])
        self.assertEqual(0, recorded["payload_shape"]["byte_size_estimate"])


class EventIdentityTest(unittest.TestCase):
    def _event(self, field_paths, operation="chat.completions.create"):
        return event.build(
            module="openai",
            mechanism="sdk_wrapper",
            operation=operation,
            target={"host_id": "api.openai.com", "provider_ref": "openai"},
            payload_shape=shape.Shape(field_paths, 100, 0, []),
            entrypoint_hint="worker",
            site={"path": "app/service.py", "symbol": "summarise"},
        )

    def test_same_call_shape_yields_one_identity(self):
        first = self._event(["messages[].content", "model"])
        second = self._event(["messages[].content", "model"])
        self.assertEqual(first["egress_event_id"], second["egress_event_id"])

    def test_size_does_not_change_identity(self):
        base = shape.Shape(["model"], 10, 0, [])
        larger = shape.Shape(["model"], 900000, 0, [])
        ids = set()
        for payload in (base, larger):
            ids.add(event.build(
                module="openai", mechanism="sdk_wrapper",
                operation="chat.completions.create",
                target={"host_id": "api.openai.com", "provider_ref": "openai"},
                payload_shape=payload, entrypoint_hint="worker",
            )["egress_event_id"])
        self.assertEqual(1, len(ids))

    def test_different_operation_yields_a_different_identity(self):
        first = self._event(["model"])
        second = self._event(["model"], operation="embeddings.create")
        self.assertNotEqual(first["egress_event_id"], second["egress_event_id"])


if __name__ == "__main__":
    unittest.main()

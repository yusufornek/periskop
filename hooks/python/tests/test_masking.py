"""Field paths carry structure. If a value ever appears in one, the tool has
become the leak it was deployed to prevent, so these are the tests that matter
most in this package.
"""

import json
import unittest

from periskop_hook import key_policy, shape
from periskop_hook.wrappers import openai_sdk

from tests import support

SECRETS = (
    "ahmet@firma.com",
    "TR330006100519786457841326",
    "sk-proj-4f9c2b7e1a8d",
    "Hastanın raporu ektedir",
    "5312345678901234",
)


class ValueLeakTest(unittest.TestCase):
    """The critical one: no value, in any position, reaches the record."""

    def _payload(self):
        return {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": SECRETS[3]},
                {"role": "system", "content": SECRETS[1]},
            ],
            "metadata": {"account": SECRETS[4]},
            # A map keyed by customer address: the key is the data here.
            "customers": {SECRETS[0]: {"balance": 12}},
            "api_key": SECRETS[2],
        }

    def test_no_value_appears_in_field_paths(self):
        described = shape.describe(self._payload())
        joined = " ".join(described.field_paths)
        for secret in SECRETS:
            self.assertNotIn(secret, joined)

    def test_no_value_appears_anywhere_in_the_written_event(self):
        module = support.fake_openai()
        openai_sdk.install(module)
        with support.event_stream() as read_events:
            module.resources.chat.completions.Completions().create(
                **self._payload())
            events = read_events()

        serialised = json.dumps(events)
        for secret in SECRETS:
            self.assertNotIn(secret, serialised)
        # The record is still useful: the recognised structure survives.
        self.assertIn("messages[].content", events[0]["payload_shape"]["field_paths"])

    def test_dynamic_keys_become_a_placeholder(self):
        described = shape.describe({"customers": {SECRETS[0]: {"balance": 12}}})
        self.assertEqual(["<dyn>.<dyn>.<dyn>"], described.field_paths)

    def test_unrecognised_field_names_are_normalised(self):
        described = shape.describe({"model": "gpt-4o", "internal_ticket": "T-42"})
        self.assertEqual(["<dyn>", "model"], described.field_paths)


class KeyPolicyTest(unittest.TestCase):
    def test_allow_list_cannot_be_widened_with_a_content_like_key(self):
        # Gate one runs when the allow list is built, so no entry that looks
        # like data can be admitted by a later edit.
        for key in ("ahmet@firma.com", "user@x.io", "1234567", "a/b", "x y"):
            self.assertTrue(key_policy.looks_like_content(key), key)
            self.assertNotIn(key, key_policy.ALLOWED_KEYS)

    def test_recognised_field_names_survive(self):
        for key in ("messages", "model", "content", "tools", "role"):
            self.assertEqual(key, key_policy.mask_key(key))

    def test_non_string_keys_are_masked(self):
        self.assertEqual(key_policy.DYNAMIC_KEY, key_policy.mask_key(7))
        self.assertEqual(key_policy.DYNAMIC_KEY, key_policy.mask_key(None))


class TraversalLimitTest(unittest.TestCase):
    def test_depth_limit_is_reported_rather_than_hidden(self):
        payload = current = {}
        for _ in range(shape.MAX_DEPTH + 3):
            child = {}
            current["content"] = child
            current = child
        described = shape.describe(payload)
        self.assertIn(shape.TRUNCATED, described.degraded_reasons)
        self.assertGreaterEqual(described.truncated_depth, shape.MAX_DEPTH)

    def test_long_sequence_is_sampled_and_declared(self):
        payload = {"messages": [{"role": "user", "content": "x" * 10}
                                for _ in range(shape.MAX_ITEMS * 4)]}
        described = shape.describe(payload)
        self.assertIn(shape.TRUNCATED, described.degraded_reasons)
        # The estimate is scaled back up, so a sampled walk does not report a
        # large payload as a small one.
        self.assertGreater(described.byte_size_estimate, 10 * shape.MAX_ITEMS)

    def test_generator_body_is_never_consumed(self):
        chunks = iter([b"one", b"two"])
        described = shape.describe({"data": chunks})
        self.assertIn(shape.STREAMING, described.degraded_reasons)
        self.assertEqual([b"one", b"two"], list(chunks))

    def test_opaque_objects_are_not_inspected(self):
        class Exploding(object):
            def __getattr__(self, name):
                raise AssertionError("the hook read an attribute")

        described = shape.describe({"model": Exploding()})
        self.assertEqual(["model"], described.field_paths)
        self.assertIn(shape.TRUNCATED, described.degraded_reasons)

    def test_the_sampled_estimate_uses_no_floating_point(self):
        # Reports have to diff byte for byte across runs and machines, and this
        # scaling was the only floating point step on the record path: the
        # division rounded to the nearest double before the truncation ran, so a
        # large enough sample could land either side of an integer depending on
        # the platform. The expectation below is computed the way the code is
        # required to compute it, in integers.
        item = "x" * 10
        payload = {"messages": [item for _ in range(1000)]}
        described = shape.describe(payload)
        sampled_bytes = len(item) * shape.MAX_ITEMS
        self.assertEqual(sampled_bytes * 1000 // shape.MAX_ITEMS,
                         described.byte_size_estimate)
        self.assertIsInstance(described.byte_size_estimate, int)


class UnwalkableBodyTest(unittest.TestCase):
    """A body that could not be read is a gap, never an empty call."""

    def test_a_body_that_is_not_a_container_declares_the_stop(self):
        # Substituting an empty mapping wrote field_paths [] with a size of 0
        # and no degraded reason, which is the record the schema reserves for a
        # call that carried nothing. A reader cannot tell the two apart, and the
        # schema is explicit that a thin event must read as thin rather than as
        # evidence of a small call.
        described = shape.describe("a body the hook cannot walk")
        self.assertEqual([], described.field_paths)
        self.assertEqual(0, described.byte_size_estimate)
        self.assertEqual(0, described.truncated_depth)
        self.assertIn(shape.TRUNCATED, described.degraded_reasons)

    def test_an_empty_mapping_still_reads_as_an_empty_call(self):
        # The other half of the same statement: a call that really carried
        # nothing must not be dressed up as a gap.
        described = shape.describe({})
        self.assertEqual([], described.field_paths)
        self.assertIsNone(described.truncated_depth)
        self.assertEqual([], described.degraded_reasons)

    def test_a_sequence_body_is_walked_the_way_the_other_hook_walks_it(self):
        # The Node hook walks a root level array; declaring this one unwalkable
        # would give one call two shapes under one identity.
        described = shape.describe([{"model": "m"}, {"model": "n"}])
        self.assertEqual(["[].model"], described.field_paths)
        self.assertIsNone(described.truncated_depth)


if __name__ == "__main__":
    unittest.main()

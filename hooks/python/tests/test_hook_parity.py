"""The two hooks have to agree, and this is where that is checked.

The Python hook and the Node hook write into one stream under one contract. The
same call recorded by both derives the same `egress_event_id`, so the collector
keeps one of the two records and discards the other without counting the
discard. Everything that differs between the two implementations therefore
decides what the report says by way of a sort order.

`hook-parity-vectors.json` is one file read by both suites. Two copies would pin
nothing: drifting apart is exactly the failure being guarded against, and two
files drift together.
"""

import json
import os
import unittest

from periskop_hook import shape, target

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "hook-parity-vectors.json")


def _vectors():
    with open(VECTORS, encoding="utf-8") as stream:
        return json.load(stream)


class FieldPathParityTest(unittest.TestCase):
    def test_every_vector_produces_the_pinned_field_paths(self):
        for case in _vectors()["field_paths"]:
            described = shape.describe(case["payload"])
            self.assertEqual(case["paths"], described.field_paths, case["name"])

    def test_every_vector_produces_the_pinned_truncated_depth(self):
        # Absent and zero are different statements: absent means the walk
        # finished, zero means it stopped at the root. A hook that wrote zero
        # for a fully described payload would report every call as one nothing
        # is known about.
        for case in _vectors()["field_paths"]:
            described = shape.describe(case["payload"])
            self.assertEqual(
                case["truncated_depth"], described.truncated_depth, case["name"])


class ProviderRefParityTest(unittest.TestCase):
    def test_every_host_classifies_the_way_the_other_hook_classifies_it(self):
        # A table that knows a provider in one language and not in the other
        # makes "the code says OpenAI, the wire says Groq" a finding that only
        # ever appears in half the processes.
        for case in _vectors()["provider_ref"]:
            self.assertEqual(
                case["provider"], target.classify(case["host"]), case["host"])


if __name__ == "__main__":
    unittest.main()

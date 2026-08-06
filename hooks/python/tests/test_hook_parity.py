"""The two hooks have to agree, and this is where that is checked.

The Python hook and the Node hook write into one stream under one contract. The
same call recorded by both derives the same `egress_event_id`, so the collector
keeps one of the two records and discards the other without counting the
discard. Everything that differs between the two implementations therefore
decides what the report says by way of a sort order.

`hooks/shared/hook-parity-vectors.json` is one file read by both suites. Two
copies would pin nothing: drifting apart is exactly the failure being guarded
against, and two files drift together.

It sits outside both hooks on purpose. The file that measures two
implementations cannot belong to one of them: while it lived under this
directory the Node suite read across into it, so this hook could have relaxed a
vector the other hook was being held to, and a rename here would have removed
the other hook's gate without failing anything.
"""

import json
import os
import unittest

from periskop_hook import key_policy, shape, target

# tests/ -> python/ -> hooks/ -> shared/. Resolved from this file rather than
# from the working directory, because the suite is discovered from hooks/python
# and a relative path would break the moment it is run from anywhere else.
VECTORS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "shared", "hook-parity-vectors.json")


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


class KeyVocabularyParityTest(unittest.TestCase):
    def test_the_admitted_vocabulary_is_the_one_the_other_hook_admits(self):
        # Entry for entry, not merely overlapping. A key one hook knows and the
        # other masks gives one call two shapes under one identity, and the
        # collector keeps whichever record sorted first. Widening the vocabulary
        # is now one edit to three files, and skipping any of the three fails
        # both suites.
        self.assertEqual(_vectors()["key_vocabulary"]["allowed"],
                         sorted(key_policy.ALLOWED_KEYS))

    def test_a_key_outside_the_shared_vocabulary_is_masked(self):
        # The other direction. Without it a hook could admit everything and
        # still pass the list above.
        self.assertEqual(key_policy.DYNAMIC_KEY,
                         key_policy.mask_key("balance_owed"))
        self.assertEqual(key_policy.DYNAMIC_KEY,
                         key_policy.mask_key("ahmet@firma.com"))


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

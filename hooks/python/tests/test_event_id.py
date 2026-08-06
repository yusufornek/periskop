"""The identity every hook has to agree on, pinned to fixed expected values.

`CROSS_LANGUAGE_VECTORS` below is duplicated verbatim in
`hooks/node/src/event-id.test.ts`. The duplication is the point: two hooks that
derive an identity differently give one call two identities and defeat
deduplication, and the only way to prove they do not is for both suites to
hardcode the same expected strings and both compute them. If either hook drifts,
one of the two suites goes red rather than reconciliation quietly double
counting.

The first vector is the contract example, `schemas/examples/egress-event.valid.json`.
"""

import os
import unittest

from periskop_hook import event, event_id, shape

from tests import support

# module, operation, host_id, path_template, expected identity
CROSS_LANGUAGE_VECTORS = (
    ("openai", "chat.completions.create", "api.openai.com",
     "/v1/chat/completions", "ee_3dfe316616cd47b4"),
    ("anthropic", "messages.create", "api.anthropic.com",
     "/v1/messages", "ee_e8f55ce3debd7846"),
    ("node:https", "post", "api.openai.com",
     "/v1/embeddings", "ee_2918520a58b33a3c"),
    ("httpx", "http.post", "api.cohere.com", "", "ee_c896832e544738fd"),
    ("requests", "http.get", "unknown", "", "ee_be40919f69bdf6d4"),
    # A non-ASCII module name, written composed. Pinned so that a hook which
    # stops composing to NFC, or composes to something else, goes red here
    # instead of quietly deriving a second identity for one call.
    ("öneri_istemcisi", "sohbet.olustur", "api.openai.com",
     "/v1/sohbet/tamamlama", "ee_a4863895e4a520cd"),
)

# The same four fields as the last vector above, with the module written in the
# decomposed spelling: `o` plus U+0308 COMBINING DIAERESIS instead of U+00F6.
# The two render identically and a reader cannot tell them apart.
DECOMPOSED_SPELLING = ("o\u0308neri_istemcisi", "sohbet.olustur",
                       "api.openai.com", "/v1/sohbet/tamamlama")


class DerivationTest(unittest.TestCase):
    def test_the_pinned_cross_language_vectors_are_reproduced(self):
        for module, operation, host, template, expected in CROSS_LANGUAGE_VECTORS:
            self.assertEqual(
                expected, event_id.derive(module, operation, host, template),
                "{0} {1}".format(module, operation))

    def test_the_contract_example_identity_is_reproduced(self):
        """The schema example is the one identity that is already published."""
        example = support.load_json(os.path.join(
            support.SCHEMA_DIR, "examples", "egress-event.valid.json"))
        self.assertEqual(
            example["egress_event_id"],
            event_id.derive(
                example["library"]["module"],
                example["operation"],
                example["target"]["host_id"],
                example["target"]["path_template"],
            ),
        )

    def test_an_absent_path_template_hashes_as_the_empty_string(self):
        # The schema makes path_template optional, so a hook that could not read
        # one has to agree with a hook that read an empty one.
        self.assertEqual(
            event_id.derive("httpx", "http.post", "api.cohere.com", None),
            event_id.derive("httpx", "http.post", "api.cohere.com", ""),
        )

    def test_every_named_field_changes_the_identity(self):
        base = ("openai", "chat.completions.create", "api.openai.com",
                "/v1/chat/completions")
        changed = (
            ("anthropic", base[1], base[2], base[3]),
            (base[0], "embeddings.create", base[2], base[3]),
            (base[0], base[1], "api.anthropic.com", base[3]),
            (base[0], base[1], base[2], "/v1/embeddings"),
        )
        for candidate in changed:
            self.assertNotEqual(
                event_id.derive(*base), event_id.derive(*candidate), candidate)

    def test_two_spellings_of_one_name_derive_one_identity(self):
        """The failure this guards is silent, which is why it is pinned here.

        Nothing rejects either spelling. Reconciliation simply never joins the
        two records, the call is reported twice, and no coverage entry says so.
        """
        composed = CROSS_LANGUAGE_VECTORS[-1][:4]
        self.assertNotEqual(composed[0], DECOMPOSED_SPELLING[0],
                            "the two spellings must really differ in bytes")
        self.assertEqual(
            event_id.derive(*composed), event_id.derive(*DECOMPOSED_SPELLING))

    def test_composition_does_not_merge_genuinely_different_names(self):
        # NFC composes; it does not fold case or strip accents. A guard against
        # reaching for NFKC or a casefold later, which would give two different
        # modules one identity.
        self.assertNotEqual(
            event_id.derive("öneri", "op", "host", "/p"),
            event_id.derive("oneri", "op", "host", "/p"),
        )

    def test_the_separator_keeps_field_boundaries_unambiguous(self):
        # Without a separator these two would serialise to the same bytes.
        self.assertNotEqual(
            event_id.derive("open", "ai.create", "host", "/p"),
            event_id.derive("openai", ".create", "host", "/p"),
        )

    def test_the_form_is_the_one_the_schema_pattern_fixes(self):
        for module, operation, host, template, _ in CROSS_LANGUAGE_VECTORS:
            self.assertRegex(
                event_id.derive(module, operation, host, template),
                r"^ee_[0-9a-f]{16}$")


class BuiltEventTest(unittest.TestCase):
    """The builder has to feed the derivation the four fields and no others."""

    def _build(self, **overrides):
        arguments = {
            "module": "openai",
            "mechanism": "sdk_wrapper",
            "operation": "chat.completions.create",
            "target": {
                "host_id": "api.openai.com",
                "port": 443,
                "path_template": "/v1/chat/completions",
                "provider_ref": "openai",
            },
            "payload_shape": shape.Shape(["model"], 100, 0, []),
            "entrypoint_hint": "billing-worker",
        }
        arguments.update(overrides)
        return event.build(**arguments)

    def test_a_built_event_carries_the_contract_identity(self):
        self.assertEqual(
            "ee_3dfe316616cd47b4", self._build()["egress_event_id"])

    def test_the_entrypoint_does_not_change_the_identity(self):
        # Two workers making one call is one call, not two.
        self.assertEqual(
            self._build()["egress_event_id"],
            self._build(entrypoint_hint="nightly-batch")["egress_event_id"],
        )

    def test_the_payload_does_not_change_the_identity(self):
        larger = shape.Shape(["messages[].content", "model"], 900000, 4, [])
        self.assertEqual(
            self._build()["egress_event_id"],
            self._build(payload_shape=larger)["egress_event_id"],
        )

    def test_the_call_site_does_not_change_the_identity(self):
        site = {"path": "services/customer.py", "symbol": "summarize"}
        self.assertEqual(
            self._build()["egress_event_id"],
            self._build(site=site)["egress_event_id"],
        )

    def test_a_target_without_a_path_template_still_yields_an_identity(self):
        built = self._build(target={"host_id": "api.cohere.com"})
        self.assertRegex(built["egress_event_id"], r"^ee_[0-9a-f]{16}$")


if __name__ == "__main__":
    unittest.main()

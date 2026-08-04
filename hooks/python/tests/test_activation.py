"""Which processes are worth instrumenting (milestone 30)."""

import unittest

from periskop_hook import activation, config


class ActivationTest(unittest.TestCase):
    def test_env_switch_turns_the_hook_off(self):
        for value in ("0", "false", "OFF", " no "):
            active, reason = activation.decide(
                ["/app/worker.py"], {"PERISKOP_HOOK": value})
            self.assertFalse(active, value)
            self.assertEqual(activation.DISABLED, reason)

    def test_package_installers_are_not_instrumented(self):
        for argv0 in ("/usr/bin/pip", "/venv/bin/pip3", "/venv/bin/uv",
                      "/venv/lib/site-packages/pip/__main__.py", "setup.py"):
            active, reason = activation.decide([argv0], {})
            self.assertFalse(active, argv0)
            self.assertTrue(reason.startswith(activation.NON_TARGET), reason)

    def test_inline_snippets_are_not_instrumented(self):
        active, reason = activation.decide(["-c"], {})
        self.assertFalse(active)
        self.assertEqual(activation.INLINE_SCRIPT, reason)

    def test_an_application_process_is_instrumented(self):
        for argv0 in ("/app/worker.py", "/usr/bin/gunicorn", "manage.py"):
            active, reason = activation.decide([argv0], {"PERISKOP_HOOK": "1"})
            self.assertTrue(active, argv0)
            self.assertEqual(activation.ACTIVE, reason)

    def test_an_empty_argv_does_not_break_the_decision(self):
        active, _ = activation.decide([], {})
        self.assertTrue(active)


class ConfigTest(unittest.TestCase):
    def test_no_output_means_no_hook(self):
        self.assertIsNone(config.load({}, ["/app/worker.py"]))

    def test_entrypoint_hint_is_never_an_absolute_path(self):
        settings = config.load(
            {"PERISKOP_HOOK_OUTPUT": "/tmp/events.jsonl"},
            ["/srv/app/billing_worker.py"],
        )
        self.assertEqual("billing_worker", settings.entrypoint_hint)

    def test_explicit_entrypoint_wins(self):
        settings = config.load(
            {"PERISKOP_HOOK_OUTPUT": "/tmp/events.jsonl",
             "PERISKOP_HOOK_ENTRYPOINT": "billing-worker"},
            ["/srv/app/main.py"],
        )
        self.assertEqual("billing-worker", settings.entrypoint_hint)

    def test_a_broken_buffer_size_falls_back_instead_of_failing(self):
        for raw in ("nonsense", "0", "-4", None):
            settings = config.load(
                {"PERISKOP_HOOK_OUTPUT": "/tmp/events.jsonl",
                 "PERISKOP_HOOK_BUFFER": raw} if raw is not None
                else {"PERISKOP_HOOK_OUTPUT": "/tmp/events.jsonl"},
                ["/app/worker.py"],
            )
            self.assertGreater(settings.buffer_capacity, 0)


if __name__ == "__main__":
    unittest.main()

"""The transport the event schema fixes: a directory, one file per process."""

import os
import re
import unittest

from periskop_hook import config


class EventDirectoryTest(unittest.TestCase):
    def _load(self, environ, pid=4711):
        return config.load(environ, ["/app/worker.py"], pid=pid)

    def test_a_directory_yields_a_jsonl_file_inside_it(self):
        settings = self._load({config.EVENT_DIR: "/var/run/periskop"})
        directory, name = os.path.split(settings.output_path)
        self.assertEqual("/var/run/periskop", directory)
        # The collector selects event files by the .jsonl extension, so a stream
        # written under any other name is a stream it never reads.
        self.assertRegex(name, r"^python-4711-[0-9a-f]{8}\.jsonl$")

    def test_two_processes_in_one_directory_never_share_a_file(self):
        first = self._load({config.EVENT_DIR: "/var/run/periskop"}, pid=1)
        second = self._load({config.EVENT_DIR: "/var/run/periskop"}, pid=2)
        self.assertNotEqual(first.output_path, second.output_path)

    def test_a_reused_pid_does_not_append_to_the_previous_run(self):
        # Pids are recycled. Without the random suffix a short lived process
        # could land on a finished one's number and merge two runs into one
        # stream that nobody can separate again.
        paths = {self._load({config.EVENT_DIR: "/var/run/periskop"}).output_path
                 for _ in range(8)}
        self.assertEqual(8, len(paths))

    def test_the_directory_is_not_created_by_reading_configuration(self):
        # Configuration is read at interpreter startup, in every process that
        # has the .pth installed. Creating a directory there would be a side
        # effect for processes that go on to record nothing.
        target = "/tmp/periskop-config-test-should-not-exist"
        self._load({config.EVENT_DIR: target})
        self.assertFalse(os.path.exists(target))

    def test_surrounding_whitespace_does_not_produce_a_stray_directory(self):
        settings = self._load({config.EVENT_DIR: "  /var/run/periskop  "})
        self.assertTrue(settings.output_path.startswith("/var/run/periskop/"))

    def test_an_empty_directory_variable_is_the_same_as_none(self):
        self.assertIsNone(self._load({config.EVENT_DIR: "   "}))


class LegacyOutputPathTest(unittest.TestCase):
    """The old single file variable keeps working, but it is not the default."""

    def test_the_legacy_path_is_used_when_no_directory_is_set(self):
        settings = config.load(
            {config.LEGACY_OUTPUT_PATH: "/tmp/events.jsonl"},
            ["/app/worker.py"], pid=7,
        )
        self.assertEqual("/tmp/events.jsonl", settings.output_path)

    def test_the_directory_model_wins_over_the_legacy_path(self):
        settings = config.load(
            {config.EVENT_DIR: "/var/run/periskop",
             config.LEGACY_OUTPUT_PATH: "/tmp/events.jsonl"},
            ["/app/worker.py"], pid=7,
        )
        self.assertTrue(settings.output_path.startswith("/var/run/periskop/"))

    def test_neither_variable_means_no_hook(self):
        self.assertIsNone(config.load({}, ["/app/worker.py"]))


class EntrypointHintTest(unittest.TestCase):
    """The field is a name. A path in it is one machine leaking into a report."""

    def _hint(self, environ, argv=("/app/worker.py",)):
        environ = dict(environ)
        environ.setdefault(config.EVENT_DIR, "/var/run/periskop")
        return config.load(environ, list(argv), pid=1).entrypoint_hint

    def test_the_operator_supplied_name_is_reduced_to_a_basename(self):
        # Without this every event carries /srv/app, the report stops diffing
        # against the same run on another host, and the schema's "never an
        # absolute path" is broken by the hook that writes the field. The schema
        # has no pattern for it, so no later stage would catch it.
        self.assertEqual(
            "worker.py",
            self._hint({"PERISKOP_HOOK_ENTRYPOINT": "/srv/app/worker.py"}))

    def test_an_operator_chosen_extension_survives(self):
        # The name is theirs. argv[0] loses its .py because the interpreter
        # chose that one, not the operator.
        self.assertEqual(
            "ingest.py", self._hint({"PERISKOP_HOOK_ENTRYPOINT": "ingest.py"}))
        self.assertEqual("worker", self._hint({}))

    def test_a_trailing_separator_is_read_the_way_the_other_hook_reads_it(self):
        # os.path.basename answers "" here and Node's basename answers "app".
        # One variable, two hooks, one hint: the divergence had to be closed in
        # one direction, and keeping the operator's last word is that direction.
        self.assertEqual(
            "app", self._hint({"PERISKOP_HOOK_ENTRYPOINT": "/srv/app/"}))

    def test_a_name_that_reduces_to_nothing_falls_back(self):
        # An empty string is a valid value for this field, so it would be
        # written and read as a process that named itself.
        self.assertEqual(
            "python", self._hint({"PERISKOP_HOOK_ENTRYPOINT": "/"}))
        self.assertEqual(
            "python", self._hint({"PERISKOP_HOOK_ENTRYPOINT": "   "}))

    def test_the_name_is_bounded(self):
        self.assertEqual(
            64, len(self._hint({"PERISKOP_HOOK_ENTRYPOINT": "n" * 200})))


class StreamNameTest(unittest.TestCase):
    def test_the_name_carries_the_language_the_pid_and_entropy(self):
        self.assertRegex(config.stream_name(1234),
                         r"^python-1234-[0-9a-f]{8}\.jsonl$")

    def test_the_name_is_a_bare_file_name(self):
        # It is joined onto a directory the operator chose; a separator here
        # would let it escape into a path nobody configured.
        self.assertNotIn(os.sep, config.stream_name(1234))

    def test_the_name_does_not_disturb_the_application_random_state(self):
        # Seeding or advancing `random` would be an observation tool changing
        # the program it observes, so the entropy comes from os.urandom.
        import random

        random.seed(20260804)
        expected = [random.random() for _ in range(3)]
        random.seed(20260804)
        config.stream_name(1)
        self.assertEqual(expected, [random.random() for _ in range(3)])


class StreamNameCollisionTest(unittest.TestCase):
    def test_names_do_not_repeat_across_many_draws(self):
        names = {config.stream_name(1) for _ in range(2000)}
        self.assertEqual(2000, len(names))
        for name in names:
            self.assertIsNotNone(
                re.match(r"^python-1-[0-9a-f]{8}\.jsonl$", name), name)


if __name__ == "__main__":
    unittest.main()

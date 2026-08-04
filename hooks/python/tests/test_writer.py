"""The ring buffer, the background drain and the status sidecar."""

import json
import os
import shutil
import tempfile
import unittest

from periskop_hook.writer import EventWriter


class _NoThreadWriter(EventWriter):
    """Writer whose drain never starts, so the ring can be observed full."""

    def _start(self):
        return None


def _event(index):
    return {"schema_version": "1.0", "operation": "chat.completions.create",
            "index": index}


class RingBufferTest(unittest.TestCase):
    def test_full_ring_drops_oldest_and_counts_the_loss(self):
        writer = _NoThreadWriter("/unused/events.jsonl", capacity=2)
        for index in range(5):
            writer.submit(_event(index))
        # Silent loss is forbidden: what fell off the ring is counted so the
        # coverage statement can say so.
        self.assertEqual(3, writer.dropped_events_count)
        # Drop oldest: the ring keeps the most recent capacity events.
        self.assertEqual([3, 4], [item["index"] for item in writer._queue])


class StreamTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="periskop-writer-test-")
        self.path = os.path.join(self.directory, "nested", "events.jsonl")

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_events_are_written_as_one_json_object_per_line(self):
        writer = EventWriter(self.path, capacity=16)
        for index in range(3):
            writer.submit(_event(index))
        writer.close()

        with open(self.path, encoding="utf-8") as stream:
            lines = [line for line in stream if line.strip()]
        self.assertEqual(3, len(lines))
        self.assertEqual(
            ["index", "operation", "schema_version"],
            list(json.loads(lines[0]).keys()),
        )

    def test_the_run_declares_itself_in_a_status_file(self):
        writer = EventWriter(self.path, capacity=16)
        writer.submit(_event(0))
        writer.close()

        with open(self.path + ".status.json", encoding="utf-8") as stream:
            status = json.load(stream)
        self.assertEqual("active", status["hook_status"])
        self.assertEqual(0, status["dropped_events_count"])
        self.assertEqual(1, status["written_events_count"])

    def test_closing_twice_is_safe(self):
        writer = EventWriter(self.path, capacity=4)
        writer.submit(_event(0))
        writer.close()
        writer.close()
        self.assertTrue(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main()

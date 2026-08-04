"""The ring buffer, the background drain and the status sidecar."""

import json
import os
import shutil
import tempfile
import unittest

from periskop_hook import failopen
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

    def test_the_status_document_is_the_one_the_collector_reads(self):
        # Property names, not just values. The node hook writes these five and
        # periskop-runtime-collector looks for them; a counter spelled
        # differently in either hook is a counter that reaches nobody, which is
        # what this whole sidecar was until the collector learned to read it.
        writer = EventWriter(self.path, capacity=16)
        writer.submit(_event(0))
        writer.close()

        with open(self.path + ".status.json", encoding="utf-8") as stream:
            status = json.load(stream)
        self.assertEqual(
            ["dropped_events_count", "failures", "hook_status", "reason",
             "written_events_count"],
            sorted(status.keys()),
        )
        # The sidecar sits beside the stream under the suffix the collector
        # selects on, and never under the stream's own extension: read back as
        # an event it would be a malformed record instead of an account of one.
        self.assertTrue(self.path.endswith(".jsonl"))

    def test_a_write_that_fails_counts_every_event_it_lost(self):
        # The failure this accounting exists for. A CI container fills its disk
        # and the append raises. The events had already been taken off the ring
        # to be written, so before this the status file read "nothing written,
        # nothing dropped" and the report called the run clean. The guard around
        # the drain only ever recorded *which* failure it was, never how many
        # events went with it.
        writer = EventWriter(self.path, capacity=16)
        for index in range(5):
            writer.submit(_event(index))
        # A directory in place of the stream: every open for append raises, the
        # way a revoked mount or a read only volume does.
        os.makedirs(self.path)
        writer.close()

        self.assertEqual(5, writer.dropped_events_count)
        self.assertEqual(0, writer.written_events_count)
        # And the failure is still named, so a full disk is distinguishable from
        # a hook that never started.
        self.assertTrue(
            any(label.startswith("writer.") for label in failopen.failures()),
            failopen.failures(),
        )

    def test_a_record_that_cannot_be_serialised_is_counted_not_dropped_quietly(self):
        # It has already left the ring by the time json.dumps refuses it, so
        # this is the last moment the loss can be counted at all.
        writer = _NoThreadWriter(self.path, capacity=16)
        writer.submit(_event(0))
        writer.submit({"payload": object()})
        writer.submit(_event(1))

        lines = writer._serialise_batch()

        self.assertEqual(2, len(lines))
        self.assertEqual(1, writer.dropped_events_count)

    def test_closing_twice_is_safe(self):
        writer = EventWriter(self.path, capacity=4)
        writer.submit(_event(0))
        writer.close()
        writer.close()
        self.assertTrue(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main()

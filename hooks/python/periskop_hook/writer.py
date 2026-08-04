"""Event sink: bounded ring in memory, one background thread doing the I/O.

No I/O happens on the call path (ADR-009 safety rules, spec section 4). The
wrapper appends a dictionary to a bounded deque and returns; serialising and
writing happen on a daemon thread. That is where the per call budget of under
1 ms comes from, and it is also why a slow or full disk cannot turn into
backpressure inside somebody else's request handler.

When the ring is full the oldest event is dropped, and the drop is counted. A
dropped event that nobody counted would be a silent hole in a coverage claim,
which the honest coverage principle forbids: the count is written to the status
file next to the stream, and `periskop-runtime-collector` reads that file back
into the coverage statement.

An overflowing ring is not the only way an event dies here. Draining takes
records off the ring before writing them, so a write that fails after the ring
has been emptied loses events that no counter would ever see: the guard around
the drain records that *something* failed, never how much went with it. On a CI
container with a full disk that difference is the whole report, so every path
out of the ring below either ends in a written line or in the drop counter.
"""

import atexit
import collections
import json
import os
import threading

from . import failopen

_JOIN_TIMEOUT_SECONDS = 2.0
_STATUS_SUFFIX = ".status.json"

ACTIVE = "active"
DISABLED = "disabled"


class EventWriter(object):
    def __init__(self, output_path, capacity):
        self._output_path = output_path
        self._queue = collections.deque(maxlen=capacity)
        self._wakeup = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self.dropped_events_count = 0
        self.written_events_count = 0

    @property
    def output_path(self):
        return self._output_path

    def submit(self, event):
        """Hand an event to the ring. Never blocks, never raises."""
        queue = self._queue
        if queue.maxlen is not None and len(queue) >= queue.maxlen:
            self.dropped_events_count += 1
        queue.append(event)
        if self._thread is None:
            # Started on first use so that a hooked process which never calls a
            # wrapped library pays for no thread at all.
            failopen.run("writer.start", self._start)
        self._wakeup.set()

    def _start(self):
        with self._lock:
            if self._thread is not None:
                return
            directory = os.path.dirname(self._output_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            thread = threading.Thread(
                target=self._drain_forever, name="periskop-hook-writer"
            )
            thread.daemon = True
            self._thread = thread
            thread.start()
            atexit.register(self.close)

    def _drain_forever(self):
        while not self._stop.is_set():
            self._wakeup.wait(0.5)
            self._wakeup.clear()
            failopen.run("writer.drain", self._drain_once)
        failopen.run("writer.drain", self._drain_once)

    def _serialise_batch(self):
        """Empty the ring into lines, counting whatever cannot be serialised.

        A record that fails to serialise has already left the ring, so counting
        it here is the last moment it can be counted at all.
        """
        lines = []
        while self._queue:
            try:
                event = self._queue.popleft()
            except IndexError:
                break
            try:
                # sort_keys keeps the stream diffable across runs.
                lines.append(
                    json.dumps(event, sort_keys=True, separators=(",", ":")))
            except Exception:
                self.dropped_events_count += 1
        return lines

    def _drain_once(self):
        if not self._queue:
            return
        lines = self._serialise_batch()
        if not lines:
            return
        try:
            with open(self._output_path, "a", encoding="utf-8") as stream:
                stream.write("\n".join(lines) + "\n")
        except Exception:
            # ENOSPC, EACCES, EDQUOT, a revoked mount. These events are gone:
            # they left the ring to be written and the write did not happen.
            # Counting them here is what turns "the disk filled up" from an
            # invisible hole in the coverage claim into a number the report
            # carries. The re-raise is deliberate, so the guard one frame up
            # still records *which* failure it was, next to *how many* it cost.
            self.dropped_events_count += len(lines)
            raise
        self.written_events_count += len(lines)

    def close(self):
        """Flush what is left and declare the run. Safe to call twice."""
        atexit.unregister(self.close)
        self._stop.set()
        self._wakeup.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(_JOIN_TIMEOUT_SECONDS)
        failopen.run("writer.close", self._drain_once)
        failopen.run("writer.status", self.write_status, ACTIVE, "")

    def write_status(self, status, reason):
        """Sidecar declaring what this process observed, and what it lost."""
        document = {
            "hook_status": status,
            "reason": reason,
            "dropped_events_count": self.dropped_events_count,
            "written_events_count": self.written_events_count,
            "failures": list(failopen.failures()),
        }
        path = self._output_path + _STATUS_SUFFIX
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True)

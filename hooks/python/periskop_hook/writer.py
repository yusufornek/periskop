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

The same file carries how long this process was watched for. Nothing in the
event schema can: `egress_event_id` is derived from the call shape and carries
no clock, which is what makes the same call recorded twice one identity, and a
stamp in the body would break both that and the determinism of the report. The
window is not a property of a call anyway. It is a property of the collection,
and it is the only thing under a claim that some call site never ran, so it
travels here as a DURATION read from a monotonic clock. Wall clock time is not
used at any point: a system clock corrected mid run would otherwise produce a
negative or an inflated window.
"""

import atexit
import collections
import json
import os
import threading
import time

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
        self._close_registered = False
        # The window opens when the hook enters the call path, which is when
        # this object is built, and not when the first call arrives. A process
        # that ran for an hour and called a provider once in the last minute was
        # watched for an hour; timing from the first event would report a minute
        # and turn fifty-nine minutes of evidence into nothing.
        self._observation_started_at = time.monotonic()
        # None while the hook is in the call path. A fixed token once it is not,
        # which is what `write_status` reads to decide what this process is
        # allowed to claim about itself.
        self._disabled_reason = None
        self.dropped_events_count = 0
        self.written_events_count = 0

    @property
    def output_path(self):
        return self._output_path

    def observation_window_ms(self):
        """Milliseconds this process has been under observation so far.

        A duration, never a stamp. Truncated rather than rounded, because a
        window is the floor of what was watched and rounding up would state a
        few tenths of a millisecond nobody observed.
        """
        elapsed = time.monotonic() - self._observation_started_at
        # A monotonic clock cannot go backwards, but a platform that ever let it
        # would put a negative window into a report, and the max costs nothing.
        return int(max(0.0, elapsed) * 1000)

    def declare(self):
        """Announce the run before any event exists. Safe to call twice.

        Without this, a process that is hooked and never calls a wrapped library
        leaves nothing on disk at all, and a directory holding no file for it
        cannot say whether it was watched for an hour or never started. That is
        exactly the run a dormancy claim is made from, so the accounting has to
        exist from the moment the hook is in place rather than from the first
        event.
        """
        failopen.run("writer.declare", self._declare)

    def _declare(self):
        directory = os.path.dirname(self._output_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._register_close()
        self.write_status()

    def _register_close(self):
        """Arrange for the final flush and status write, exactly once."""
        if self._close_registered:
            return
        self._close_registered = True
        atexit.register(self.close)

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
            self._register_close()

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
        # The accounting is rewritten with every batch, not only at exit. A
        # process killed by an OOM handler or a container stop never reaches
        # close(), and without this it would leave a stream of events beside a
        # window nobody measured, which suppresses every claim those events were
        # collected to support. What the sidecar then holds is the window as of
        # the last flush: a lower bound, which can only understate the run.
        failopen.run("writer.status", self.write_status)

    def close(self):
        """Flush what is left and declare the run. Safe to call twice."""
        atexit.unregister(self.close)
        self._stop.set()
        self._wakeup.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(_JOIN_TIMEOUT_SECONDS)
        failopen.run("writer.close", self._drain_once)
        failopen.run("writer.status", self.write_status)

    def mark_disabled(self, reason):
        """Take this stream out of the call path and say so on disk.

        `reason` is a fixed token from the hook's own vocabulary, never free
        text: the collector copies it into a report, and the status contract
        pins the character set for exactly that reason.

        Without this the sidecar was written as `active` from every call site,
        so a startup that opened the stream and then failed before instrumenting
        anything left an `active` document beside an empty stream. A run reading
        that pair sees a process that was watched and made no calls, which is
        the shape of a clean result and the one reading spec section 5 forbids.
        The Node hook has derived its status from a disable reason since it was
        written; this is the same statement in this language.
        """
        self._disabled_reason = reason
        failopen.run("writer.status", self.write_status)

    def write_status(self):
        """Sidecar declaring what this process observed, and what it lost.

        Contract: `schemas/hook-status.schema.json`. The property names are read
        back by `periskop-runtime-collector`; a counter spelled differently here
        is a counter that reaches nobody.

        The status is derived rather than passed in. A caller that could choose
        it could claim a hook was active while it was not, and every caller did
        choose `active`.
        """
        disabled = self._disabled_reason
        document = {
            "hook_status": ACTIVE if disabled is None else DISABLED,
            "reason": "" if disabled is None else disabled,
            "dropped_events_count": self.dropped_events_count,
            "written_events_count": self.written_events_count,
            "failures": list(failopen.failures()),
            "observation_window_ms": self.observation_window_ms(),
        }
        path = self._output_path + _STATUS_SUFFIX
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True)

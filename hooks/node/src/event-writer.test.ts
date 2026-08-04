import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";

import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { FileEventSink, streamName } from "./event-writer";
import { resetStatus, snapshot, startObservation } from "./hook-status";
import type { EgressEvent } from "./egress-event";

function event(id: string): EgressEvent {
  return {
    schema_version: "1.0",
    egress_event_id: id,
    process: { language: "javascript", runtime: "node/20" },
    library: { module: "node:https", mechanism: "http_client" },
    operation: "post",
    target: { host_id: "api.openai.com" },
    payload_shape: { field_paths: ["model"], byte_size_estimate: 12 },
  };
}

function sandbox(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "periskop-hook-test-"));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("events reach the file as one JSON object per line", (t) => {
  resetStatus();
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 100, 16);
  sink.record(event("ee_0000000000000001"));
  sink.record(event("ee_0000000000000002"));
  sink.close();

  const lines = readFileSync(sink.eventPath, "utf8").trim().split("\n");
  assert.equal(lines.length, 2);
  for (const line of lines) {
    const parsed = JSON.parse(line) as EgressEvent;
    assert.match(parsed.egress_event_id, /^ee_[0-9a-f]{16}$/);
  }
});

test("recording does not put file I/O on the call path", (t) => {
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 101, 16);
  sink.record(event("ee_0000000000000003"));
  // Nothing has been written yet: the drain is on a timer that does not hold
  // the process open, which is what keeps the budget at a memory append.
  assert.throws(() => readFileSync(sink.eventPath, "utf8"));
  sink.close();
  assert.ok(readFileSync(sink.eventPath, "utf8").includes("ee_0000000000000003"));
});

test("the buffer is bounded, and what it drops is counted", (t) => {
  resetStatus();
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 102, 4);
  for (let i = 0; i < 10; i += 1) {
    sink.record(event(`ee_00000000000000${i.toString(16).padStart(2, "0")}`));
  }
  sink.close();

  const lines = readFileSync(sink.eventPath, "utf8").trim().split("\n");
  assert.equal(lines.length, 4);
  // Drop-oldest, so the events that survive are the most recent ones.
  assert.ok(lines[0]?.includes("ee_0000000000000006"));
  assert.equal(snapshot().dropped_events_count, 6);
  assert.equal(snapshot().written_events_count, 4);
});

test("a write that fails counts every event it lost", (t) => {
  // The failure this accounting exists for. A CI container fills its disk, five
  // thousand calls are observed, and the write fails. The batch had already
  // left the buffer, so before this the counters read "nothing recorded, nothing
  // dropped" and the report called the run clean. The buffer is not emptied
  // until the write returns, so the loss is countable in every outcome.
  resetStatus();
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 108, 16);
  sink.record(event("ee_0000000000000007"));
  sink.record(event("ee_0000000000000008"));
  // The stream's own directory is removed underneath it, which is what a
  // revoked mount or a cleaned scratch space looks like from in here.
  rmSync(dir, { recursive: true, force: true });
  sink.close();

  assert.equal(snapshot().dropped_events_count, 2);
  assert.equal(snapshot().written_events_count, 0);
  // And the failure is named, so an operator can tell a full disk from a hook
  // that was never installed.
  assert.deepEqual(snapshot().failures, ["writer.flush"]);
});

test("the status document is the one the collector reads", (t) => {
  // Property names, not just values. The Python hook writes these six and
  // periskop-runtime-collector looks for them; a counter spelled differently
  // here is a counter that reaches nobody, which is what "dropped_events"
  // used to be.
  resetStatus();
  startObservation();
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 109, 16);
  sink.record(event("ee_0000000000000009"));
  sink.close();

  const status = JSON.parse(readFileSync(sink.statusPath, "utf8")) as Record<string, unknown>;
  assert.deepEqual(Object.keys(status).sort(), [
    "dropped_events_count",
    "failures",
    "hook_status",
    "observation_window_ms",
    "reason",
    "written_events_count",
  ]);
  assert.equal(status["hook_status"], "active");
  assert.equal(status["written_events_count"], 1);
  assert.equal(status["dropped_events_count"], 0);
});

test("the status carries how long the process was watched, as a duration", (t) => {
  // The one number every claim about a call that did NOT happen rests on.
  // Without it the collector reads the run as unmeasured and every
  // dormant_egress_point finding is suppressed, which is what happened in every
  // real run before the field existed.
  resetStatus();
  startObservation();
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 110, 16);
  sink.record(event("ee_000000000000000a"));
  sink.close();

  const status = JSON.parse(readFileSync(sink.statusPath, "utf8")) as Record<string, unknown>;
  const window = status["observation_window_ms"];
  assert.equal(typeof window, "number");
  assert.ok((window as number) >= 0);
  // A duration, never a stamp. An epoch millisecond value would be around
  // 1.7e12 and would put a clock into output that has to be diffable.
  assert.ok((window as number) < 60 * 60 * 1000, `${String(window)} looks like a clock`);
});

test("a hook that never entered the call path states no window at all", (t) => {
  // Absent, not zero. Zero says the hook was watching for no time; absent says
  // it cannot say. The collector decides dormancy differently for each, so a
  // hook that wrote 0 here would let a run conclude from an unmeasured silence.
  resetStatus();
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 111, 16);
  sink.record(event("ee_000000000000000b"));
  sink.close();

  const status = JSON.parse(readFileSync(sink.statusPath, "utf8")) as Record<string, unknown>;
  assert.ok(!("observation_window_ms" in status), JSON.stringify(status));
});

test("a process killed before close still leaves the window it reached", async (t) => {
  // A container stop never reaches close(). The sidecar is rewritten on every
  // flush so that such a process leaves a lower bound rather than nothing,
  // because nothing suppresses every finding the events it did write support.
  // The drain is left to its own timer here rather than forced, so what is
  // proved is the path a killed process actually takes.
  resetStatus();
  startObservation();
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 112, 16);
  t.after(() => sink.close());
  sink.record(event("ee_000000000000000c"));
  await new Promise((resolve) => setTimeout(resolve, 400));

  const status = JSON.parse(readFileSync(sink.statusPath, "utf8")) as Record<string, unknown>;
  assert.equal(status["written_events_count"], 1);
  assert.equal(typeof status["observation_window_ms"], "number");
});

test("the hook's own account of itself lands beside the events, not inside them", (t) => {
  resetStatus();
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 103, 16);
  sink.record(event("ee_0000000000000004"));
  sink.close();

  // .json, not .jsonl: the collector selects event files by extension, and a
  // run's own accounting read back as an event would be a malformed record.
  assert.ok(sink.statusPath.endsWith(".status.json"));
  assert.ok(!sink.statusPath.endsWith(".jsonl"));
  const status = JSON.parse(readFileSync(sink.statusPath, "utf8")) as Record<string, unknown>;
  assert.equal(status["hook_status"], "active");
  assert.equal(status["written_events_count"], 1);
  assert.equal(status["dropped_events_count"], 0);
});

test("the stream is a .jsonl file named after the process that writes it", (t) => {
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 105, 16);
  // The extension is what periskop-runtime-collector selects on, so anything
  // else is a stream it never reads.
  assert.match(basename(sink.eventPath), /^node-105-[0-9a-f]{8}\.jsonl$/);
});

test("two processes writing into one directory never share a file", (t) => {
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  // This is the whole reason the contract names a directory rather than a file:
  // two writers appending to one file interleave and corrupt lines, and here
  // nobody has to coordinate to avoid it.
  const first = new FileEventSink(dir, 106, 16);
  const second = new FileEventSink(dir, 107, 16);
  assert.notEqual(first.eventPath, second.eventPath);

  // Pids are reused, so the same pid twice has to be two files as well, or a
  // new run would append to a finished one's stream.
  assert.notEqual(streamName(106), streamName(106));
});

test("closing twice is harmless, and recording after close is a no-op", (t) => {
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 104, 16);
  sink.record(event("ee_0000000000000005"));
  sink.close();
  sink.close();
  sink.record(event("ee_0000000000000006"));

  const contents = readFileSync(sink.eventPath, "utf8");
  assert.ok(contents.includes("ee_0000000000000005"));
  assert.ok(!contents.includes("ee_0000000000000006"));
});

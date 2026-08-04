import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileEventSink } from "./event-writer";
import { resetStatus, snapshot } from "./hook-status";
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
  assert.equal(snapshot().dropped_events, 6);
  assert.equal(snapshot().recorded_events, 10);
});

test("the hook's own account of itself lands beside the events, not inside them", (t) => {
  resetStatus();
  const { dir, cleanup } = sandbox();
  t.after(cleanup);

  const sink = new FileEventSink(dir, 103, 16);
  sink.record(event("ee_0000000000000004"));
  sink.close();

  const status = JSON.parse(readFileSync(join(dir, "node-103.status.json"), "utf8")) as Record<
    string,
    unknown
  >;
  assert.equal(status["status"], "active");
  assert.equal(status["recorded_events"], 1);
  assert.equal(status["dropped_events"], 0);
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

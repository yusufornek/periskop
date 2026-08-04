// What the server may say about a source, and what it may not.
//
// Every test here runs without the engine binary, on purpose. The states that
// matter most are the ones a static only pipeline cannot produce: a run with a
// network sensor behind it, and a report from an engine that predates a field.
// A suite that could only go through the real binary would leave both untested
// and would still pass, which is how a hard coded answer survived this long.

import assert from "node:assert/strict";
import test from "node:test";

import {
  SENSOR_NOT_RUNNING,
  SENSOR_RUNNING,
  UNKNOWN,
  countUnmatchedWireTraffic,
  flowBuckets,
  networkSensor,
  reconciliationMode,
} from "./sources.js";
import type { Coverage, Finding } from "./tools.js";

/** A coverage statement carrying only the fields a static scan has always had. */
function coverage(overrides: Partial<Coverage> = {}): Coverage {
  return {
    parsed_files: 10,
    unparsed_files: [],
    undetected_libraries: [],
    runtime_coverage: [],
    ...overrides,
  };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    finding_id: "fnd_7c1e4a90b3d25f61",
    provider_ref: "openai",
    confidence: "confirmed",
    detector: { rule_id: "py.openai.chat_completions" },
    kind: "declared_egress_point",
    source: "declared",
    ...overrides,
  };
}

test("not running and unknown are different words", () => {
  // The whole distinction rests on a reader being able to tell them apart. If
  // the two constants ever converge, every test below still passes and the
  // server starts answering an unasked question with a claim.
  assert.notEqual(SENSOR_NOT_RUNNING, UNKNOWN);
  assert.notEqual(SENSOR_RUNNING, UNKNOWN);
});

test("a report that does not state its mode is unknown, not static_only", () => {
  // Filling in the commonest mode would be the same lie in a quieter form: the
  // reader would be told one source spoke when nothing said how many did.
  assert.equal(reconciliationMode(coverage()), UNKNOWN);
});

test("the mode is passed through as the report spells it", () => {
  for (const mode of ["full", "static_only", "static_plus_runtime", "static_plus_wire"]) {
    assert.equal(reconciliationMode(coverage({ reconciliation_mode: mode })), mode);
  }
});

test("a mode this server has not been taught is passed through rather than flattened", () => {
  // It is what the report says, and the reader can look it up. Rewriting it to
  // unknown would destroy information the server was actually given.
  assert.equal(
    reconciliationMode(coverage({ reconciliation_mode: "static_plus_something" })),
    "static_plus_something",
  );
});

test("a run whose mode includes the wire says the sensor was running", () => {
  for (const mode of ["full", "static_plus_wire"]) {
    assert.equal(networkSensor(coverage({ reconciliation_mode: mode })), SENSOR_RUNNING, mode);
  }
});

test("a run whose mode excludes the wire says the sensor was not running", () => {
  for (const mode of ["static_only", "static_plus_runtime"]) {
    assert.equal(networkSensor(coverage({ reconciliation_mode: mode })), SENSOR_NOT_RUNNING, mode);
  }
});

test("a report with no mode leaves the sensor unknown rather than not running", () => {
  // The two cases this pair of tests separates: a report that says no sensor
  // fed the run, and a report that says nothing at all. Answering the second
  // with the words of the first is a claim about the machine made out of the
  // server's own ignorance.
  const silent = networkSensor(coverage());
  assert.equal(silent, UNKNOWN);
  assert.notEqual(silent, networkSensor(coverage({ reconciliation_mode: "static_only" })));
});

test("a mode this server does not know leaves the sensor unknown rather than guessed", () => {
  assert.equal(networkSensor(coverage({ reconciliation_mode: "static_plus_something" })), UNKNOWN);
});

test("a pcap run with no stated platform still reports its sensor as running", () => {
  // The engine writes sensor_platform_class none whenever the capture mechanism
  // does not identify a platform, which pcap never does. Reading the sensor
  // state off that field would report the sensor as absent on every macOS run.
  const pcap = coverage({ reconciliation_mode: "full" });
  assert.equal(networkSensor(pcap), SENSOR_RUNNING);
});

test("the four buckets are null when the report omits them, not zero", () => {
  // Zero says the sensor counted nothing. Null says nobody counted. Only one of
  // them is true of a report that never carried the field.
  assert.deepEqual(flowBuckets(coverage()), {
    out_of_scope_flows: null,
    known_benign_flows: null,
    unattributed_flows: null,
    unclassified_flows: null,
  });
});

test("the four buckets carry the numbers the report states, including zero", () => {
  const counted = coverage({
    out_of_scope_flows: 12,
    known_benign_flows: 3,
    unattributed_flows: 0,
    unclassified_flows: 7,
  });
  assert.deepEqual(flowBuckets(counted), {
    out_of_scope_flows: 12,
    known_benign_flows: 3,
    unattributed_flows: 0,
    unclassified_flows: 7,
  });
});

test("unmatched wire traffic is counted apart from every other kind", () => {
  const findings = [
    finding(),
    finding({ finding_id: "fnd_0000000000000002", kind: "unmatched_wire_traffic", source: "reconciled" }),
    finding({ finding_id: "fnd_0000000000000003", kind: "target_drift", source: "reconciled" }),
    finding({ finding_id: "fnd_0000000000000004", kind: "unmatched_wire_traffic", source: "reconciled" }),
  ];
  assert.equal(countUnmatchedWireTraffic(findings), 2);
});

test("a report with no findings counts zero unmatched wire traffic", () => {
  assert.equal(countUnmatchedWireTraffic([]), 0);
});

test("findings that do not state their kind make the count unknown rather than zero", () => {
  // An engine older than the field produces these. Zero would answer none to a
  // question that was never asked, and it is the one finding kind whose absence
  // a reader is most likely to act on. Written out rather than built from the
  // helper because the point is the missing field, not an undefined one.
  const older: Finding[] = [
    {
      finding_id: "fnd_0000000000000005",
      provider_ref: "openai",
      confidence: "confirmed",
      detector: { rule_id: "py.openai.chat_completions" },
    },
  ];
  assert.equal(countUnmatchedWireTraffic(older), null);
});

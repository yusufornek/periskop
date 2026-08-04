// The reconciliation trace.
//
// Split between two kinds of test on purpose.
//
// The projection is checked against recorded findings. A reconciled finding is
// produced by a run with a second source in it, and a static only pipeline has
// none, so a test that could only go through the real binary could not reach the
// code that matters here at all.
//
// The refusals are checked against the real binary, following the smoke test:
// what a static scan does produce is declared findings, and the property worth
// nailing down is that the tool turns those away with the contract's code rather
// than inventing a trace for a finding that has no reconciliation under it.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

import { EngineBridge, type ReportSource } from "./bridge.js";
import {
  DEFAULT_TRACE_DEPTH,
  MAX_TRACE_DEPTH,
  trace,
  traceReconciliation,
} from "./reconciliation.js";
import type { Finding, ScanReport } from "./report.js";
import { runScan } from "./tools.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const binary = process.env["PERISKOP_BINARY"] ?? path.join(repoRoot, "target/debug/periskop");
const rules = path.join(repoRoot, "rules");
const fixtures = path.join(repoRoot, "crates/periskop-static-scanner/fixtures/python");
const available = existsSync(binary);

const POINT = "ep_3f0a91c7d4e28b56";
const EVENT = "ee_5b18c30af7924de6";

/** A target drift, shaped as the reconciliation engine emits one. */
function drift(overrides: Partial<Finding> = {}): Finding {
  return {
    finding_id: "fnd_7c1e4a90b3d25f61",
    kind: "target_drift",
    source: "reconciled",
    provider_ref: "openai",
    confidence: "confirmed",
    detector: { rule_id: "any.reconciled.target-drift" },
    refs: [
      { ref_type: "egress_point", ref_id: POINT },
      { ref_type: "egress_event", ref_id: EVENT },
    ],
    evidence: [
      {
        evidence_type: "reconciliation_join",
        ref: "J2:operation_only declared=api.openai.com:443 observed=llm-gateway.internal:443 drift=host_changed",
      },
    ],
    ...overrides,
  };
}

function report(findings: Finding[], suspects: Finding[] = []): ScanReport {
  return {
    report_id: "rpt_0000000000000001",
    scan_run_id: "scan_0000000000000001",
    verdict: "WARN",
    findings,
    suspect_findings: suspects,
    coverage: {
      parsed_files: 1,
      unparsed_files: [],
      undetected_libraries: [],
      runtime_coverage: [],
    },
  };
}

/** A bridge that answers with a recorded report instead of starting a process. */
function source(scan: ScanReport): ReportSource {
  return { call: () => Promise.resolve(scan) };
}

test("a drift trace names the rung, the two destinations and the sources", async () => {
  const result = (await traceReconciliation(source(report([drift()])), {
    path: ".",
    finding_id: "fnd_7c1e4a90b3d25f61",
  })) as {
    join_path: Array<{ join: string; outcome: string; key_fields: string[]; from_ref: string | null; to_ref: string | null }>;
    contributing_sources: Array<{ source: string; detector_id: string | null }>;
    discrepancy: { kind: string; expected: string; observed: string } | null;
    truncated: boolean;
    coverage_note: string | null;
  };

  assert.equal(result.join_path.length, 1);
  const step = result.join_path[0];
  assert.ok(step);
  assert.equal(step.join, "J2");
  assert.equal(step.outcome, "operation_only");
  // The rung is what the claim rests on, so which fields it agreed on is the
  // part a reader has to be able to check.
  assert.deepEqual(step.key_fields, ["operation"]);
  assert.equal(step.from_ref, POINT);
  assert.equal(step.to_ref, EVENT);

  assert.deepEqual(result.discrepancy, {
    kind: "host_changed",
    expected: "api.openai.com:443",
    observed: "llm-gateway.internal:443",
  });
  assert.deepEqual(
    result.contributing_sources.map((entry) => entry.source),
    ["declared", "observed-app"],
  );
  assert.equal(result.truncated, false);
  // Nothing was silently substituted for the missing per source detector ids.
  assert.match(result.coverage_note ?? "", /detector ids are reported as null/);
});

test("a finding that was not derived is refused rather than traced", async () => {
  const declared = drift({
    finding_id: "fnd_0000000000000002",
    kind: "declared_egress_point",
    source: "declared",
    evidence: [{ evidence_type: "ast_node", ref: "call:openai.chat.completions.create" }],
  });

  const result = (await traceReconciliation(source(report([declared])), {
    path: ".",
    finding_id: "fnd_0000000000000002",
  })) as { error?: { code: string; retryable: boolean; message: string } };

  assert.equal(result.error?.code, "TRACE_UNSUPPORTED");
  assert.equal(result.error?.retryable, false);
  // The answer says which tool does cover this case, so the refusal is not a
  // dead end.
  assert.match(result.error?.message ?? "", /data flow trace/);
});

test("an identifier from another scan is not found rather than empty", async () => {
  const result = (await traceReconciliation(source(report([drift()])), {
    path: ".",
    finding_id: "fnd_ffffffffffffffff",
  })) as { error?: { code: string } };

  // An empty trace and an unknown finding read identically and mean opposite
  // things, which is exactly the confusion the coverage principle exists for.
  assert.equal(result.error?.code, "FINDING_NOT_FOUND");
});

test("a suspect finding is reachable, because confidence is not the trace's business", async () => {
  const suspect = drift({ confidence: "suspect" });
  const result = (await traceReconciliation(source(report([], [suspect])), {
    path: ".",
    finding_id: "fnd_7c1e4a90b3d25f61",
  })) as { join_path: unknown[] };

  assert.equal(result.join_path.length, 1);
});

test("the first call does not dump every join step", async () => {
  // The property worth guarding: a point that drifted to many destinations must
  // not put its whole join ladder into the caller's context in one response.
  const many = drift({
    evidence: Array.from({ length: 8 }, (_, index) => ({
      evidence_type: "reconciliation_join",
      ref: `J2:target_only declared=api.openai.com:443 observed=gw-${index}.internal:443 drift=host_changed`,
    })),
  });

  const result = (await traceReconciliation(source(report([many])), {
    path: ".",
    finding_id: "fnd_7c1e4a90b3d25f61",
    max_depth: 3,
  })) as { join_path: unknown[]; truncated: boolean; coverage_note: string | null };

  assert.equal(result.join_path.length, 3);
  assert.equal(result.truncated, true);
  // What was left out and how to get it, rather than a silently short list.
  assert.match(result.coverage_note ?? "", /5 of 8 join steps were left out/);
  assert.match(result.coverage_note ?? "", /max_depth=3/);
});

test("a depth outside the contract range is an error envelope, not a thrown schema", async () => {
  for (const depth of [0, MAX_TRACE_DEPTH + 1]) {
    const result = (await traceReconciliation(source(report([drift()])), {
      path: ".",
      finding_id: "fnd_7c1e4a90b3d25f61",
      max_depth: depth,
    })) as { error?: { code: string; message: string } };

    assert.equal(result.error?.code, "INVALID_ARGUMENT", `depth ${depth}`);
    assert.match(result.error?.message ?? "", new RegExp(`1 and ${MAX_TRACE_DEPTH}`));
  }
});

test("an unreadable join step is reported rather than dropped", async () => {
  // A step that vanishes makes the ladder look shorter than it was, and a
  // shorter ladder reads as stronger evidence than the finding actually has.
  const broken = drift({
    evidence: [
      { evidence_type: "reconciliation_join", ref: "not a join reference" },
      { evidence_type: "sdk_call_trace", ref: "openai.chat" },
    ],
  });

  const result = trace(broken, DEFAULT_TRACE_DEPTH) as {
    join_path: Array<{ outcome: string; key_fields: string[] }>;
    discrepancy: unknown;
    coverage_note: string | null;
  };

  assert.equal(result.join_path.length, 1);
  assert.equal(result.join_path[0]?.outcome, "unrecognised");
  assert.deepEqual(result.join_path[0]?.key_fields, []);
  assert.equal(result.discrepancy, null);
  assert.match(result.coverage_note ?? "", /could not be read/);
  assert.match(result.coverage_note ?? "", /another type/);
});

test("a dormant point has no difference to report", async () => {
  const dormant = drift({
    kind: "dormant_egress_point",
    refs: [{ ref_type: "egress_point", ref_id: POINT }],
    evidence: [
      {
        evidence_type: "reconciliation_join",
        ref: "J2:none observation_window_ms=3600000 observed_calls=0 unlinked_events=0",
      },
    ],
  });

  const result = trace(dormant, DEFAULT_TRACE_DEPTH) as {
    join_path: Array<{ outcome: string; key_fields: string[]; to_ref: string | null }>;
    contributing_sources: Array<{ source: string }>;
    discrepancy: unknown;
  };

  assert.equal(result.join_path[0]?.outcome, "none");
  assert.deepEqual(result.join_path[0]?.key_fields, []);
  assert.equal(result.join_path[0]?.to_ref, null);
  // Nothing was observed, so there is no observed value to put opposite the
  // declared one. Inventing one would be the whole failure mode this tool is
  // supposed to prevent.
  assert.equal(result.discrepancy, null);
  assert.deepEqual(
    result.contributing_sources.map((entry) => entry.source),
    ["declared"],
  );
});

test("a finding that lost its refs and evidence reports the loss, not an empty join", async () => {
  // Both lists defaulted to empty, and the answer that came out said two things
  // that cannot be true of a reconciled finding: no source contributed to it,
  // and nothing was left out of this response. A finding is reconciled because a
  // join tied at least two records together, so zero of either is a report of
  // this projection's own blindness written in the words of a fact.
  const stripped = drift();
  delete stripped.refs;
  delete stripped.evidence;

  const result = trace(stripped, DEFAULT_TRACE_DEPTH) as {
    join_path: unknown;
    contributing_sources: unknown;
    coverage_note: string | null;
  };

  assert.equal(result.contributing_sources, null);
  assert.equal(result.join_path, null);
  assert.match(result.coverage_note ?? "", /no refs field/);
  assert.match(result.coverage_note ?? "", /no evidence field/);
});

test("empty lists are reported too, and are named as empty rather than absent", async () => {
  // The other half of the same loss. A field that arrived empty and a field that
  // never arrived are two different reports, and the note says which one this
  // was so the reader knows whether to look at the engine or at its version.
  const emptied = drift({ refs: [], evidence: [] });

  const result = trace(emptied, DEFAULT_TRACE_DEPTH) as {
    contributing_sources: unknown;
    coverage_note: string | null;
  };

  assert.equal(result.contributing_sources, null);
  assert.match(result.coverage_note ?? "", /an empty refs list/);
  assert.match(result.coverage_note ?? "", /an empty evidence list/);
});

test("a join step that names one side of the difference is not dropped in silence", async () => {
  // Dropping it produced discrepancy: null, and null is the dormant answer:
  // nothing was observed. This rung says something was observed and names it.
  // The reader was handed the reverse of what the engine found.
  const halfNamed = drift({
    evidence: [
      {
        evidence_type: "reconciliation_join",
        ref: "J2:target_only observed=llm-gateway.internal:443 drift=host_changed",
      },
    ],
  });

  const result = trace(halfNamed, DEFAULT_TRACE_DEPTH) as {
    discrepancy: unknown;
    coverage_note: string | null;
  };

  assert.equal(result.discrepancy, null);
  assert.match(result.coverage_note ?? "", /named one side of the difference/);
  // The sentence the null must not be read as, said out loud.
  assert.match(result.coverage_note ?? "", /does not state that nothing was observed/);
});

test("a rung that names neither side stays silent, because that is the dormant case", async () => {
  // The note above must not appear here, or it appears on every dormant point
  // and stops being read.
  const dormant = drift({
    evidence: [
      {
        evidence_type: "reconciliation_join",
        ref: "J2:none observation_window_ms=3600000 observed_calls=0",
      },
    ],
  });

  const result = trace(dormant, DEFAULT_TRACE_DEPTH) as {
    discrepancy: unknown;
    coverage_note: string | null;
  };

  assert.equal(result.discrepancy, null);
  assert.doesNotMatch(result.coverage_note ?? "", /named one side of the difference/);
});

test("an outcome named after an Object member is unrecognised, not inherited", async () => {
  // A plain index reaches the prototype chain, so the key list for outcome
  // `constructor` was Object's constructor function: a truthy answer, so the
  // step was reported as recognised and its key fields came out of the
  // language's own object rather than out of the engine's join.
  const inherited = drift({
    refs: [{ ref_type: "constructor", ref_id: "ep_0000000000000001" }],
    evidence: [{ evidence_type: "reconciliation_join", ref: "J2:constructor declared=a observed=b" }],
  });

  const result = trace(inherited, DEFAULT_TRACE_DEPTH) as {
    join_path: Array<{ outcome: string; key_fields: unknown }>;
    contributing_sources: unknown;
    coverage_note: string | null;
  };

  assert.deepEqual(result.join_path[0]?.key_fields, []);
  assert.match(result.coverage_note ?? "", /not one this server has a key list for/);
  // The same lookup on the reference side: `constructor` is not a source.
  assert.equal(result.contributing_sources, null);
  assert.match(result.coverage_note ?? "", /not mapped to a source/);
});

test("an engine answer that is not a report is an envelope, not a thrown TypeError", async () => {
  const result = (await traceReconciliation({ call: () => Promise.resolve({ result: "ok" }) }, {
    path: ".",
    finding_id: "fnd_7c1e4a90b3d25f61",
  })) as { error?: { code: string; message: string; retryable: boolean } };

  assert.equal(result.error?.code, "CORE_UNAVAILABLE");
  assert.equal(result.error?.retryable, false);
  assert.match(result.error?.message ?? "", /cannot read as a scan report/);
});

test("a real scan's findings are turned away with the contract's code", { skip: !available }, async () => {
  const engine = new EngineBridge({ binary, rulesDir: rules, timeoutMs: 60_000 });
  try {
    const scan = (await runScan(engine, { path: fixtures, limit: 1 })) as {
      findings: Array<{ finding_id: string }>;
    };
    const first = scan.findings[0];
    assert.ok(first, "the fixture set should produce at least one finding");

    const result = (await traceReconciliation(engine, {
      path: fixtures,
      finding_id: first.finding_id,
    })) as { error?: { code: string } };

    // This build reconciles nothing, so every finding a scan produces is
    // declared. The tool has to say that rather than return an empty trace that
    // would read as "no sources contributed".
    assert.equal(result.error?.code, "TRACE_UNSUPPORTED");
  } finally {
    await engine.close();
  }
});

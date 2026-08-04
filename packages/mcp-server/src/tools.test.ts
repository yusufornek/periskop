// What the two summarising tools put in front of a reader.
//
// Checked against recorded reports rather than the engine, for the reason the
// reconciliation tests give: the answers that matter here belong to runs with a
// second and a third source, and a static only pipeline produces none of them.
// The smoke test covers the other half, that the engine and this side agree on
// the wire, and it is skipped whenever the binary is not built.

import assert from "node:assert/strict";
import test from "node:test";

import type { ReportSource } from "./bridge.js";
import type { Coverage, Finding, ScanReport } from "./report.js";
import {
  HOOKS_INSTRUMENTED,
  HOOKS_NOT_INSTRUMENTED,
  SENSOR_NOT_RUNNING,
  SENSOR_RUNNING,
  UNKNOWN,
} from "./sources.js";
import { getCoverage, getDetail, runScan, scanInput } from "./tools.js";

/**
 * The shape of a scan answer, named once because seven tests read it.
 *
 * An alias rather than an interface: only an alias is comparable to the
 * `Record<string, unknown>` the tools return, so this is what lets the cast
 * below stay a cast rather than a trip through `unknown`.
 */
type ScanAnswer = {
  summary: {
    confirmed: number;
    suspected: number;
    unmatched_wire_traffic: number | null;
    by_provider: Record<string, { confirmed: number; suspect: number }>;
  };
  findings: Array<{ finding_id: string; confidence: string }>;
  page: {
    confidence: string;
    cursor: number;
    limit: number;
    next_cursor: number | null;
    total: number;
    other: { confidence: string; total: number; fetch_with: { filter: { confidence: string } } };
  };
};

/** A coverage statement as a run with all three sources writes one. */
function fullCoverage(overrides: Partial<Coverage> = {}): Coverage {
  return {
    parsed_files: 42,
    unparsed_files: [],
    undetected_libraries: [],
    runtime_coverage: [{ language: "python", status: "instrumented" }],
    reconciliation_mode: "full",
    in_scope_flows: 30,
    out_of_scope_flows: 9,
    known_benign_flows: 4,
    unattributed_flows: 2,
    unclassified_flows: 1,
    ...overrides,
  };
}

/**
 * A statement from an engine that predates the observation fields.
 *
 * `runtime_coverage` is left out rather than set to an empty list, because those
 * are two different reports and the server owes them two different answers: one
 * never carried the field, the other named no language.
 */
function olderCoverage(): Coverage {
  return {
    parsed_files: 42,
    unparsed_files: [],
    undetected_libraries: [],
  };
}

function unmatched(id: string): Finding {
  return {
    finding_id: id,
    provider_ref: "openai",
    confidence: "confirmed",
    detector: { rule_id: "any.reconciled.unmatched-wire-traffic" },
    kind: "unmatched_wire_traffic",
    source: "reconciled",
  };
}

function declared(id: string): Finding {
  return {
    finding_id: id,
    provider_ref: "openai",
    confidence: "confirmed",
    detector: { rule_id: "py.openai.chat_completions" },
    kind: "declared_egress_point",
    source: "declared",
    location: { path: "src/summarize.py", span: { start_line: 42 } },
  };
}

/**
 * A finding the engine could not confirm.
 *
 * Every unmatched wire finding is one of these on a run without hooks, which is
 * every run of a project that has not installed them, so this is the ordinary
 * case rather than an edge one.
 */
function suspected(id: string, provider = "openai"): Finding {
  return {
    finding_id: id,
    provider_ref: provider,
    confidence: "suspect",
    detector: { rule_id: "any.reconciled.unmatched-wire-traffic" },
    kind: "unmatched_wire_traffic",
    source: "reconciled",
  };
}

function source(coverage: Coverage, findings: Finding[], suspects: Finding[] = []): ReportSource {
  const report: ScanReport = {
    report_id: "rpt_0000000000000001",
    scan_run_id: "scan_0000000000000001",
    verdict: "WARN",
    findings,
    suspect_findings: suspects,
    coverage,
  };
  return { call: () => Promise.resolve(report) };
}

/** A bridge that answers with something that is not a report at all. */
function answering(value: unknown): ReportSource {
  return { call: () => Promise.resolve(value) };
}

test("a scan with a network sensor does not report the sensor as absent", async () => {
  // The case the hard coded false was wrong about. A run that watched the wire
  // and a run that never looked produced the same answer, and the second is the
  // one the reader would have acted on.
  const result = (await runScan(source(fullCoverage(), [unmatched("fnd_0000000000000001")]), {
    path: ".",
  })) as { coverage: { network_sensor: string } };

  assert.equal(result.coverage.network_sensor, SENSOR_RUNNING);
});

test("a scan whose report is silent about its sources says unknown, not not running", async () => {
  const result = (await runScan(source(olderCoverage(), [declared("fnd_0000000000000002")]), {
    path: ".",
  })) as { coverage: { network_sensor: string }; summary: { reconciliation_mode: string } };

  assert.equal(result.coverage.network_sensor, UNKNOWN);
  assert.notEqual(result.coverage.network_sensor, SENSOR_NOT_RUNNING);
  assert.equal(result.summary.reconciliation_mode, UNKNOWN);
});

test("the summary says how many sources fed the run", async () => {
  const result = (await runScan(source(fullCoverage(), [declared("fnd_0000000000000003")]), {
    path: ".",
  })) as { summary: { reconciliation_mode: string } };

  assert.equal(result.summary.reconciliation_mode, "full");
});

test("a run with a hook attached says the hooks were instrumented", async () => {
  // The first of the three states the boolean could hold, and the only one it
  // ever got right.
  const result = (await runScan(source(fullCoverage(), [declared("fnd_0000000000001001")]), {
    path: ".",
  })) as { coverage: { runtime_hooks: string } };

  assert.equal(result.coverage.runtime_hooks, HOOKS_INSTRUMENTED);
});

test("a run whose languages all report no hook says the hooks were not attached", async () => {
  // The second state. Both statuses mean no hook ran, and the report named the
  // languages, so this is a claim the report actually supports.
  const noHooks = fullCoverage({
    runtime_coverage: [
      { language: "python", status: "not_instrumented" },
      { language: "go", status: "unsupported" },
    ],
  });

  const result = (await runScan(source(noHooks, [declared("fnd_0000000000001002")]), {
    path: ".",
  })) as { coverage: { runtime_hooks: string } };

  assert.equal(result.coverage.runtime_hooks, HOOKS_NOT_INSTRUMENTED);
});

test("a report that names no language says unknown, not that the hooks were absent", async () => {
  // The third state, and the one the boolean could not hold. `some()` over a
  // list that is empty or was never sent answers false, and false was published
  // as "the hooks were not attached": a claim about the reader's machine made
  // out of a list this server never received. It is the same substitution the
  // sensor field made one line below, and it is worse here, because an unhooked
  // run is the explanation a reader reaches for when a flow went unmatched.
  const named = fullCoverage({ runtime_coverage: [] });
  const empty = (await runScan(source(named, [declared("fnd_0000000000001003")]), {
    path: ".",
  })) as { coverage: { runtime_hooks: string } };
  const absent = (await runScan(source(olderCoverage(), [declared("fnd_0000000000001004")]), {
    path: ".",
  })) as { coverage: { runtime_hooks: string } };

  assert.equal(empty.coverage.runtime_hooks, UNKNOWN);
  assert.equal(absent.coverage.runtime_hooks, UNKNOWN);
  // The distinction the three states exist for: unknown must not be spelled the
  // way a report that stated no hooks would be.
  assert.notEqual(empty.coverage.runtime_hooks, HOOKS_NOT_INSTRUMENTED);
  assert.notEqual(absent.coverage.runtime_hooks, HOOKS_NOT_INSTRUMENTED);
});

test("the coverage tool keeps null for a runtime list the report never sent", async () => {
  // An empty array here would read as "every language was checked and none was
  // hooked", which is the sentence the summary field refuses to write.
  const result = (await getCoverage(source(olderCoverage(), []), { path: "." })) as {
    runtime_coverage: unknown;
  };

  assert.equal(result.runtime_coverage, null);
});

test("unmatched wire traffic is counted apart from the confidence totals", async () => {
  // Three findings, one of which is the claim the product is built on. Folded
  // into confirmed it would be indistinguishable from two ordinary call sites.
  const result = (await runScan(
    source(
      fullCoverage(),
      [declared("fnd_0000000000000004"), unmatched("fnd_0000000000000005")],
      [unmatched("fnd_0000000000000006")],
    ),
    { path: "." },
  )) as {
    summary: { confirmed: number; suspected: number; unmatched_wire_traffic: number | null };
  };

  assert.equal(result.summary.confirmed, 2);
  assert.equal(result.summary.suspected, 1);
  // Both lists, because unmatched wire traffic is a kind and those two are
  // confidences.
  assert.equal(result.summary.unmatched_wire_traffic, 2);
});

test("the summary stays a summary", async () => {
  // The new fields are counts and a word. A list here would be the thing the
  // page exists to prevent.
  const result = (await runScan(source(fullCoverage(), [unmatched("fnd_0000000000000007")]), {
    path: ".",
  })) as { summary: Record<string, unknown> };

  assert.equal(typeof result.summary["unmatched_wire_traffic"], "number");
  assert.equal(typeof result.summary["reconciliation_mode"], "string");
  assert.ok(!Array.isArray(result.summary["unmatched_wire_traffic"]));
  // Counts per provider, never the findings themselves. A hundred call sites to
  // one provider must cost the caller one entry, not a hundred rows.
  const providers = result.summary["by_provider"] as Record<string, unknown>;
  assert.ok(!Array.isArray(providers));
  for (const counts of Object.values(providers)) {
    assert.deepEqual(Object.keys(counts as object).sort(), ["confirmed", "suspect"]);
  }
});

test("coverage shows the four buckets that produce no finding, over what was seen", async () => {
  const result = (await getCoverage(source(fullCoverage(), []), { path: "." })) as {
    flow_buckets: Record<string, number | null>;
    network_sensor: string;
    reconciliation_mode: string;
  };

  assert.deepEqual(result.flow_buckets, {
    in_scope_flows: 30,
    out_of_scope_flows: 9,
    known_benign_flows: 4,
    unattributed_flows: 2,
    unclassified_flows: 1,
  });
  assert.equal(result.network_sensor, SENSOR_RUNNING);
  assert.equal(result.reconciliation_mode, "full");
});

test("a bucket count is never returned without the count it is read against", async () => {
  // The failure this guards: nine flows out of scope says nothing on its own.
  // Against thirty in scope it is a quarter of the traffic, against forty
  // thousand it is noise, and a reader given only the numerator cannot tell
  // which claim was made.
  const result = (await getCoverage(source(fullCoverage(), []), { path: "." })) as {
    flow_buckets: Record<string, number | null>;
  };

  assert.ok("in_scope_flows" in result.flow_buckets);
  assert.equal(result.flow_buckets["in_scope_flows"], 30);
});

test("coverage buckets are null, not zero, when the report never counted them", async () => {
  // Five zeros beside an unknown sensor would read as a machine that stayed
  // quiet. Nothing here watched it. The denominator follows the same rule: a
  // zero there would claim the sensor saw no traffic at all.
  const result = (await getCoverage(source(olderCoverage(), []), { path: "." })) as {
    flow_buckets: Record<string, number | null>;
    network_sensor: string;
  };

  assert.deepEqual(result.flow_buckets, {
    in_scope_flows: null,
    out_of_scope_flows: null,
    known_benign_flows: null,
    unattributed_flows: null,
    unclassified_flows: null,
  });
  assert.equal(result.network_sensor, UNKNOWN);
});

test("a run with hooks but no sensor says the sensor was not running", async () => {
  const runtimeOnly = fullCoverage({
    reconciliation_mode: "static_plus_runtime",
    in_scope_flows: 0,
    out_of_scope_flows: 0,
    known_benign_flows: 0,
    unattributed_flows: 0,
    unclassified_flows: 0,
  });

  const result = (await getCoverage(source(runtimeOnly, []), { path: "." })) as {
    network_sensor: string;
    flow_buckets: Record<string, number | null>;
  };

  // Zeros are correct here and mean what they say only because the sensor state
  // is beside them: the run had no wire source, so nothing was counted.
  assert.equal(result.network_sensor, SENSOR_NOT_RUNNING);
  assert.equal(result.flow_buckets["out_of_scope_flows"], 0);
});

test("findings the engine only suspects can be read, not only counted", async () => {
  // The run this product is built for: a project with no hooks installed, where
  // every unmatched wire finding is suspected. The summary said three flows had
  // nothing explaining them and no page, cursor or identifier could reach one of
  // them, so the central claim was visible as a number and nowhere else.
  const suspects = [
    suspected("fnd_0000000000000101"),
    suspected("fnd_0000000000000102"),
    suspected("fnd_0000000000000103"),
  ];
  const reports = source(fullCoverage(), [], suspects);

  const first = (await runScan(reports, { path: "." })) as ScanAnswer;
  assert.equal(first.summary.suspected, 3);
  assert.equal(first.summary.unmatched_wire_traffic, 3);
  assert.deepEqual(first.findings, []);
  assert.equal(first.page.total, 0);
  // The counted findings are somewhere, and the answer says where.
  assert.equal(first.page.other.total, 3);

  const page = (await runScan(reports, {
    path: ".",
    filter: { confidence: "suspect" },
  })) as ScanAnswer;
  assert.deepEqual(
    page.findings.map((f) => f.finding_id),
    ["fnd_0000000000000101", "fnd_0000000000000102", "fnd_0000000000000103"],
  );

  // The whole point of reaching them: an identifier that get_finding_detail
  // accepts. A count the caller cannot turn into a name is not a finding.
  const detail = (await getDetail(reports, {
    path: ".",
    finding_id: "fnd_0000000000000102",
  })) as { finding?: Finding; error?: string };
  assert.equal(detail.error, undefined);
  assert.equal(detail.finding?.finding_id, "fnd_0000000000000102");
});

test("the two lists never share a page", async () => {
  // Merging them would be the other way to make suspects reachable, and it
  // would cost the reader the one thing they need: whether the engine proved
  // this or guessed it.
  const reports = source(
    fullCoverage(),
    [declared("fnd_0000000000000201"), unmatched("fnd_0000000000000202")],
    [suspected("fnd_0000000000000203")],
  );

  const confirmed = (await runScan(reports, {
    path: ".",
    filter: { confidence: "confirmed" },
  })) as ScanAnswer;
  assert.deepEqual(
    confirmed.findings.map((f) => f.finding_id),
    ["fnd_0000000000000201", "fnd_0000000000000202"],
  );
  // Written out rather than as `every(...)`, which passes on an empty page and
  // on a page whose rows lost the field: both are exactly the states this test
  // is here to catch, and both used to satisfy it.
  assert.deepEqual(
    confirmed.findings.map((f) => f.confidence),
    ["confirmed", "confirmed"],
  );

  const suspect = (await runScan(reports, {
    path: ".",
    filter: { confidence: "suspect" },
  })) as ScanAnswer;
  assert.deepEqual(
    suspect.findings.map((f) => f.finding_id),
    ["fnd_0000000000000203"],
  );
  assert.deepEqual(
    suspect.findings.map((f) => f.confidence),
    ["suspect"],
  );
});

test("a report that contradicts itself about a finding's confidence says so", async () => {
  // The two lists and the per finding field state the same thing twice, and
  // nothing checked that they agree. A finding the engine labelled suspect,
  // sitting in the confirmed list, was paged under confidence: confirmed and
  // read as something the engine had proved.
  const mislabelled: Finding = { ...declared("fnd_0000000000001101"), confidence: "suspect" };
  const reports = source(fullCoverage(), [declared("fnd_0000000000001102"), mislabelled]);

  const result = (await runScan(reports, { path: "." })) as ScanAnswer & {
    coverage_note: string | null;
  };

  // The row is returned as the engine sent it, rather than being corrected or
  // dropped: this server does not know which half of the report is wrong.
  assert.deepEqual(
    result.findings.map((f) => f.confidence),
    ["confirmed", "suspect"],
  );
  assert.match(result.coverage_note ?? "", /1 of the 2 findings in the confirmed list/);
});

test("a report that agrees with itself carries no note", async () => {
  // A note on every answer stops being read.
  const result = (await runScan(
    source(fullCoverage(), [declared("fnd_0000000000001201")], [suspected("fnd_0000000000001202")]),
    { path: "." },
  )) as { coverage_note: string | null };

  assert.equal(result.coverage_note, null);
});

test("a finding with no span is not given line 1", async () => {
  // The default put `src/app.py:1` in front of a reader who opened the file at
  // the import block, found nothing that could have produced the finding and
  // concluded the detector was broken. Nothing in the answer said the line was
  // this server's invention.
  const spanless: Finding = {
    finding_id: "fnd_0000000000001301",
    provider_ref: "openai",
    confidence: "confirmed",
    detector: { rule_id: "py.openai.chat_completions" },
    kind: "declared_egress_point",
    source: "declared",
    location: { path: "src/app.py" },
  };
  const pathless: Finding = { ...spanless, finding_id: "fnd_0000000000001302" };
  delete pathless.location;

  const result = (await runScan(source(fullCoverage(), [spanless, pathless]), {
    path: ".",
  })) as { findings: Array<{ location: string | null }> };

  // The file is still named, because the report carried it. The line is not,
  // because the report did not.
  assert.equal(result.findings[0]?.location, "src/app.py");
  assert.notEqual(result.findings[0]?.location, "src/app.py:1");
  // A finding with no path at all keeps its null: there is nothing to open.
  assert.equal(result.findings[1]?.location, null);
});

test("a finding that states its line still carries it", async () => {
  const result = (await runScan(source(fullCoverage(), [declared("fnd_0000000000001401")]), {
    path: ".",
  })) as { findings: Array<{ location: string | null }> };

  assert.equal(result.findings[0]?.location, "src/summarize.py:42");
});

test("an engine answer that is not a report is an envelope, not a thrown TypeError", async () => {
  // `as ScanReport` checks nothing at run time, so each of these reached the
  // projection and failed inside it. The caller received a crash naming a line
  // in this server rather than an error naming the answer that caused it.
  const answers: Array<[string, unknown]> = [
    ["a different result shape", { result: "ok" }],
    ["a null findings list", { ...scanReportFixture(), findings: null }],
    ["no coverage statement", { ...scanReportFixture(), coverage: undefined }],
    ["not an object at all", "scan complete"],
    ["nothing", null],
  ];

  for (const [name, answer] of answers) {
    const scan = (await runScan(answering(answer), { path: "." })) as {
      error?: { code: string; message: string; retryable: boolean };
    };
    assert.equal(scan.error?.code, "CORE_UNAVAILABLE", name);
    assert.equal(scan.error?.retryable, false, name);
    // The answer says what was wrong with it, not just that something was.
    assert.match(scan.error?.message ?? "", /cannot read as a scan report/, name);

    const detail = (await getDetail(answering(answer), {
      path: ".",
      finding_id: "fnd_0000000000000001",
    })) as { error?: { code: string } };
    assert.equal(detail.error?.code, "CORE_UNAVAILABLE", name);

    const coverage = (await getCoverage(answering(answer), { path: "." })) as {
      error?: { code: string };
    };
    assert.equal(coverage.error?.code, "CORE_UNAVAILABLE", name);
  }
});

test("a stale identifier is refused in the same envelope as every other failure", async () => {
  // One tool answering with two shapes of error, an object here and a bare
  // string there, is a caller writing two checks and forgetting the second.
  const result = (await getDetail(source(fullCoverage(), [declared("fnd_0000000000001601")]), {
    path: ".",
    finding_id: "fnd_ffffffffffffffff",
  })) as { error?: { code: string; message: string; retryable: boolean } };

  assert.equal(result.error?.code, "FINDING_NOT_FOUND");
  assert.equal(result.error?.retryable, false);
  // Why it is stale, rather than only that it is: content addressed identifiers
  // move when the code moves.
  assert.match(result.error?.message ?? "", /rescan if the code changed/);
});

test("a finding whose fields are the wrong type is refused rather than half read", async () => {
  // Dropping the row instead would be the silent loss the check exists to
  // prevent: a scan that reported one finding fewer than the engine found, with
  // nothing in the answer saying so.
  const broken = {
    ...scanReportFixture(),
    findings: [{ finding_id: "fnd_0000000000001501", provider_ref: "openai", confidence: 3 }],
  };

  const result = (await runScan(answering(broken), { path: "." })) as {
    error?: { code: string; message: string };
  };

  assert.equal(result.error?.code, "CORE_UNAVAILABLE");
  // Which field, so the reader can tell an old engine from a broken one.
  assert.match(result.error?.message ?? "", /findings\.0\.confidence/);
});

/** A report that would pass, so that a test can spoil exactly one thing about it. */
function scanReportFixture(): ScanReport {
  return {
    report_id: "rpt_0000000000000001",
    scan_run_id: "scan_0000000000000001",
    verdict: "PASS",
    findings: [],
    suspect_findings: [],
    coverage: fullCoverage(),
  };
}

test("a page says which list it came from", async () => {
  // A reader who cannot see which list a page is has to infer it from the rows,
  // and an empty page carries no rows to infer from.
  const reports = source(
    fullCoverage(),
    [declared("fnd_0000000000000301")],
    [suspected("fnd_0000000000000302")],
  );

  const byDefault = (await runScan(reports, { path: "." })) as ScanAnswer;
  assert.equal(byDefault.page.confidence, "confirmed");

  const suspect = (await runScan(reports, {
    path: ".",
    filter: { confidence: "suspect" },
  })) as ScanAnswer;
  assert.equal(suspect.page.confidence, "suspect");
});

test("the suspected list is paged like the confirmed one", async () => {
  const reports = source(fullCoverage(), [], [
    suspected("fnd_0000000000000401"),
    suspected("fnd_0000000000000402"),
    suspected("fnd_0000000000000403"),
  ]);

  const first = (await runScan(reports, {
    path: ".",
    filter: { confidence: "suspect" },
    limit: 1,
  })) as ScanAnswer;
  assert.equal(first.findings.length, 1);
  assert.equal(first.page.total, 3);
  assert.equal(first.page.next_cursor, 1);

  const last = (await runScan(reports, {
    path: ".",
    filter: { confidence: "suspect" },
    limit: 1,
    cursor: 2,
  })) as ScanAnswer;
  assert.deepEqual(
    last.findings.map((f) => f.finding_id),
    ["fnd_0000000000000403"],
  );
  assert.equal(last.page.next_cursor, null);
});

test("the answer names the argument that reaches the other list", async () => {
  // Structured rather than described, so that reaching the rest of the findings
  // does not depend on the caller having read the tool description.
  const reports = source(
    fullCoverage(),
    [declared("fnd_0000000000000501")],
    [suspected("fnd_0000000000000502"), suspected("fnd_0000000000000503")],
  );

  const confirmed = (await runScan(reports, { path: "." })) as ScanAnswer;
  assert.deepEqual(confirmed.page.other, {
    confidence: "suspect",
    total: 2,
    fetch_with: { filter: { confidence: "suspect" } },
  });

  const suspect = (await runScan(reports, {
    path: ".",
    filter: { confidence: "suspect" },
  })) as ScanAnswer;
  assert.deepEqual(suspect.page.other, {
    confidence: "confirmed",
    total: 1,
    fetch_with: { filter: { confidence: "confirmed" } },
  });
});

test("the named argument is one the tool actually accepts", async () => {
  // What deepEqual above cannot check: that fetch_with names live arguments
  // rather than a shape the input schema stopped accepting. Nesting the filter
  // is exactly the kind of change that leaves the hint pointing at an argument
  // the tool rejects, and a caller following it would land on the list it was
  // already reading.
  const reports = source(
    fullCoverage(),
    [declared("fnd_0000000000000801")],
    [suspected("fnd_0000000000000802"), suspected("fnd_0000000000000803")],
  );

  const first = (await runScan(reports, { path: "." })) as ScanAnswer;
  const followed = (await runScan(
    reports,
    scanInput.parse({ path: ".", ...first.page.other.fetch_with }),
  )) as ScanAnswer;

  assert.equal(followed.page.confidence, "suspect");
  assert.deepEqual(
    followed.findings.map((f) => f.finding_id),
    ["fnd_0000000000000802", "fnd_0000000000000803"],
  );
});

test("a provider seen only in suspected findings is not left out", async () => {
  // The provider breakdown was answered from the confirmed findings alone, so a
  // project whose only egress was suspected reported no providers at all, which
  // reads as a project that talks to nobody.
  const reports = source(
    fullCoverage(),
    [declared("fnd_0000000000000601")],
    [suspected("fnd_0000000000000602", "acme")],
  );

  const result = (await runScan(reports, { path: "." })) as ScanAnswer;
  assert.deepEqual(result.summary.by_provider, {
    acme: { confirmed: 0, suspect: 1 },
    openai: { confirmed: 1, suspect: 0 },
  });
});

test("the provider breakdown counts findings and does not pool the two lists", async () => {
  // Two things at once, because the field has to answer both. A list of names
  // could not say that openai carries three of the four findings, and a single
  // pooled integer per provider could not say that one of those three is only
  // suspected. Merging them inside the count would undo, in one number, the
  // separation the two lists exist to keep.
  const reports = source(
    fullCoverage(),
    [declared("fnd_0000000000000701"), declared("fnd_0000000000000702")],
    [suspected("fnd_0000000000000703"), suspected("fnd_0000000000000704", "acme")],
  );

  const result = (await runScan(reports, { path: "." })) as ScanAnswer;
  assert.deepEqual(result.summary.by_provider, {
    acme: { confirmed: 0, suspect: 1 },
    openai: { confirmed: 2, suspect: 1 },
  });
});

test("the provider breakdown is ordered, so two runs of one report agree byte for byte", async () => {
  // Determinism is a stated property of every answer here (CLAUDE.md). Map
  // insertion order follows the findings, so an engine that emitted the same
  // findings in another order would otherwise produce a different serialisation
  // of the same facts and every diff of two reports would be noise.
  const reports = source(
    fullCoverage(),
    [declared("fnd_0000000000000901")],
    [suspected("fnd_0000000000000902", "zeta"), suspected("fnd_0000000000000903", "acme")],
  );

  const result = (await runScan(reports, { path: "." })) as ScanAnswer;
  assert.deepEqual(Object.keys(result.summary.by_provider), ["acme", "openai", "zeta"]);
});

test("a page of suspected findings is still a page", async () => {
  // Reachable must not mean returned all at once. Thirty suspected findings in
  // one response is the context emptying this tool exists to avoid.
  const many = Array.from({ length: 30 }, (_, i) =>
    suspected(`fnd_00000000000007${String(i).padStart(2, "0")}`),
  );

  const result = (await runScan(source(fullCoverage(), [], many), {
    path: ".",
    filter: { confidence: "suspect" },
  })) as ScanAnswer;

  assert.equal(result.findings.length, 20);
  assert.equal(result.page.total, 30);
  assert.equal(result.page.next_cursor, 20);
});

test("the two tools answer the sensor question with the same word", async () => {
  // One fact, one vocabulary. Two spellings of the same state would let a reader
  // conclude the tools disagree about the run.
  const coverage = fullCoverage({ reconciliation_mode: "static_plus_wire" });
  const scan = (await runScan(source(coverage, []), { path: "." })) as {
    coverage: { network_sensor: string };
  };
  const report = (await getCoverage(source(coverage, []), { path: "." })) as {
    network_sensor: string;
  };

  assert.equal(scan.coverage.network_sensor, report.network_sensor);
});

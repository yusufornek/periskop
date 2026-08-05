// End to end check across the language boundary.
//
// The unit tests on either side prove that the Rust engine scans and that the
// TypeScript shapes a response. Neither proves the two agree on the wire, which
// is where a project with a bridge usually breaks: a field renamed on one side,
// a framing assumption that holds in one language and not the other.
//
// So this starts the real binary, sends real requests and reads real answers.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

import { EngineBridge } from "./bridge.js";
import { HOOKS_NOT_INSTRUMENTED, SENSOR_NOT_RUNNING } from "./sources.js";
import { getCoverage, getDetail, runScan } from "./tools.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const binary = process.env["PERISKOP_BINARY"] ?? path.join(repoRoot, "target/debug/periskop");
const rules = path.join(repoRoot, "rules");
const fixtures = path.join(repoRoot, "crates/periskop-static-scanner/fixtures/python");

// A missing engine fails this suite rather than skipping it.
//
// Skipping was the earlier behaviour and it was wrong in a way worth spelling
// out: these are the only tests that check the two languages agree on the wire,
// so a run without the binary reported success while proving nothing. Opting
// out is still possible, but it now takes an explicit environment variable,
// which is an act rather than an accident.
const optedOut = process.env["PERISKOP_SKIP_ENGINE_TESTS"] === "1";
const available = existsSync(binary);

test("the engine binary is present", { skip: optedOut }, () => {
  assert.ok(
    available,
    `no engine at ${binary}. Build it with "cargo build -p periskop-cli", point ` +
      `PERISKOP_BINARY at one, or set PERISKOP_SKIP_ENGINE_TESTS=1 to state that ` +
      `this run is not checking the language boundary.`,
  );
});

function bridge(): EngineBridge {
  return new EngineBridge({ binary, rulesDir: rules, timeoutMs: 60_000 });
}

test("the engine answers a ping", { skip: !available }, async () => {
  const engine = bridge();
  try {
    assert.deepEqual(await engine.call("ping"), { ok: true });
  } finally {
    await engine.close();
  }
});

test("a scan crosses the boundary intact", { skip: !available }, async () => {
  const engine = bridge();
  try {
    const result = (await runScan(engine, { path: fixtures })) as {
      verdict: string;
      summary: {
        confirmed: number;
        suspected: number;
        by_provider: Record<string, { confirmed: number; suspect: number }>;
        reconciliation_mode: string;
        unmatched_wire_traffic: number | null;
      };
      findings: unknown[];
      coverage: { files_read: number; runtime_hooks: string };
    };

    // WARN rather than PASS, and that is the correct answer. The fixture set
    // includes a call matched only by the text of its URL, which reports as
    // suspected, and the default policy raises a warning when anything is merely
    // suspected. Asserting PASS here would mean asserting that a weaker finding
    // reaches the reader with no signal attached to it.
    assert.equal(result.verdict, "WARN");
    assert.ok(result.summary.confirmed >= 4, `expected findings, got ${result.summary.confirmed}`);
    assert.ok(result.summary.suspected >= 1, "the suspected list should not be empty here");
    // Counted from real findings rather than a recorded report, which is what
    // proves the engine sends a provider on every one of them: a finding whose
    // provider_ref went missing over the wire would land under another key here
    // and this count would fall short of the list total.
    const openai = result.summary.by_provider["openai"];
    assert.ok(openai, "the fixtures call openai and the breakdown does not name it");
    assert.ok(openai.confirmed > 0, `expected confirmed openai findings, got ${openai.confirmed}`);
    const counted = Object.values(result.summary.by_provider).reduce(
      (total, entry) => total + entry.confirmed + entry.suspect,
      0,
    );
    assert.equal(counted, result.summary.confirmed + result.summary.suspected);

    // The regression this field was rebuilt around, checked against the engine
    // rather than a recorded report. The fixture set has a call matched only by
    // the text of its URL, which the engine reports as suspected under a provider
    // no confirmed finding names, so a breakdown answered from the confirmed list
    // alone would drop that name entirely.
    const suspectOnly = Object.entries(result.summary.by_provider).filter(
      ([, entry]) => entry.confirmed === 0 && entry.suspect > 0,
    );
    assert.ok(
      suspectOnly.length > 0,
      "the engine reported a provider only suspected findings name, and it is not in the breakdown",
    );
    assert.ok(result.coverage.files_read > 0);

    // This run has one source, and the answer has to say so. A reader weighing
    // the findings above needs to know that nothing here watched the machine.
    assert.equal(result.summary.reconciliation_mode, "static_only");
    // Zero rather than null: the count is only null when the findings do not
    // state their kind, so this also proves the engine sends the field.
    assert.equal(result.summary.unmatched_wire_traffic, 0);
    // The hook state read from a real report rather than a recorded one. This
    // build ships no hooks, so the engine names the language and says no hook
    // ran; the answer may say that only because the engine did. An engine that
    // stopped sending the list would turn this to unknown, which is the state a
    // recorded report cannot prove the engine never sends.
    assert.equal(result.coverage.runtime_hooks, HOOKS_NOT_INSTRUMENTED);
  } finally {
    await engine.close();
  }
});

test("the first page is a page, not the whole result", { skip: !available }, async () => {
  // The property worth guarding: a large scan must not empty the caller's
  // context in one response.
  const engine = bridge();
  try {
    const result = (await runScan(engine, { path: fixtures, limit: 2 })) as {
      findings: unknown[];
      page: { total: number; next_cursor: number | null };
    };
    assert.equal(result.findings.length, 2);
    assert.ok(result.page.total > 2);
    assert.equal(result.page.next_cursor, 2);
  } finally {
    await engine.close();
  }
});

test("the findings the engine only suspects can be paged too", { skip: !available }, async () => {
  // The half the recorded reports cannot check: that the list the engine really
  // fills is the one this side really pages. The fixture set has a call matched
  // only by the text of its URL, so this asserts against a suspected finding the
  // engine produced rather than one a test wrote.
  const engine = bridge();
  try {
    const confirmed = (await runScan(engine, { path: fixtures })) as {
      summary: { suspected: number };
      page: { confidence: string; other: { confidence: string; total: number } };
    };
    assert.equal(confirmed.page.confidence, "confirmed");
    assert.equal(confirmed.page.other.confidence, "suspect");
    assert.equal(confirmed.page.other.total, confirmed.summary.suspected);

    const suspected = (await runScan(engine, {
      path: fixtures,
      filter: { confidence: "suspect" },
    })) as {
      findings: Array<{ finding_id: string; confidence: string }>;
      page: { confidence: string; total: number };
    };
    assert.equal(suspected.page.confidence, "suspect");
    assert.equal(suspected.page.total, confirmed.summary.suspected);

    const first = suspected.findings[0];
    assert.ok(first, "the engine reported suspected findings and none of them reached the page");
    assert.equal(first.confidence, "suspect");

    // The identifier is good for something, which is the whole claim.
    const detail = (await getDetail(engine, { path: fixtures, finding_id: first.finding_id })) as {
      finding?: { finding_id: string };
      error?: string;
    };
    assert.equal(detail.error, undefined);
    assert.equal(detail.finding?.finding_id, first.finding_id);
  } finally {
    await engine.close();
  }
});

test("coverage states what was not running", { skip: !available }, async () => {
  const engine = bridge();
  try {
    const coverage = (await getCoverage(engine, { path: fixtures })) as {
      network_sensor: string;
      reconciliation_mode: string;
      flow_buckets: Record<string, number | null>;
      runtime_coverage: Array<{ status: string }>;
    };
    // Derived from the report rather than asserted by this server, so what is
    // really being checked is that the engine states its mode and that a static
    // only run reads as one source.
    assert.equal(coverage.reconciliation_mode, "static_only");
    assert.equal(coverage.network_sensor, SENSOR_NOT_RUNNING);
    assert.ok(coverage.runtime_coverage.every((r) => r.status === "not_instrumented"));
  } finally {
    await engine.close();
  }
});

test("the flow buckets and their denominator cross the boundary as numbers", { skip: !available }, async () => {
  // The half a recorded report cannot check: whether the engine actually sends
  // these fields. A null here would mean the wire dropped them, and the server
  // would be counting nothing while looking like it counted zero. in_scope_flows
  // is the newest of the five, so it is also where a report schema that moved
  // ahead of this side would show up first.
  const engine = bridge();
  try {
    const coverage = (await getCoverage(engine, { path: fixtures })) as {
      flow_buckets: Record<string, number | null>;
    };
    assert.deepEqual(coverage.flow_buckets, {
      in_scope_flows: 0,
      out_of_scope_flows: 0,
      known_benign_flows: 0,
      unattributed_flows: 0,
      unclassified_flows: 0,
    });
  } finally {
    await engine.close();
  }
});

test("the engine names the rule set it used", { skip: !available }, async () => {
  // Same half a recorded report cannot check. The contract gate derives the
  // surface from a reference document, so it proves this server passes the
  // field through and proves nothing about whether the engine sends one.
  //
  // Both branches are driven, because one value is not evidence that the field
  // tracks anything. The bridge above names a rules directory, so it has to
  // answer "directory"; a bridge that names none reaches the set built into the
  // binary. A field stuck on either value passes one of these and fails the
  // other.
  const named = bridge();
  try {
    const result = (await runScan(named, { path: fixtures })) as {
      coverage: { rule_set_source?: string };
    };
    assert.equal(result.coverage.rule_set_source, "directory");
  } finally {
    await named.close();
  }

  const builtIn = new EngineBridge({ binary, timeoutMs: 60_000 });
  try {
    const result = (await runScan(builtIn, { path: fixtures })) as {
      coverage: { rule_set_source?: string };
    };
    assert.equal(result.coverage.rule_set_source, "embedded");
  } finally {
    await builtIn.close();
  }
});

test("one process serves many requests", { skip: !available }, async () => {
  // Restarting per call would pay rule compilation every time, which dominates
  // the cost of a small scan.
  const engine = bridge();
  try {
    const first = await engine.call("ping");
    const second = await engine.call("ping");
    assert.deepEqual(first, second);
  } finally {
    await engine.close();
  }
});

test("a bad request is answered rather than fatal", { skip: !available }, async () => {
  const engine = bridge();
  try {
    await assert.rejects(() => engine.call("no_such_method"), /unknown method/);
    // The session survives, which is the point.
    assert.deepEqual(await engine.call("ping"), { ok: true });
  } finally {
    await engine.close();
  }
});

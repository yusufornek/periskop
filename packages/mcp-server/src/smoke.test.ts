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
import { getCoverage, runScan } from "./tools.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const binary = process.env["PERISKOP_BINARY"] ?? path.join(repoRoot, "target/debug/periskop");
const rules = path.join(repoRoot, "rules");
const fixtures = path.join(repoRoot, "crates/periskop-static-scanner/fixtures/python");

const available = existsSync(binary);

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
      summary: { confirmed: number; providers: string[] };
      findings: unknown[];
      coverage: { files_read: number };
    };

    assert.equal(result.verdict, "PASS");
    assert.ok(result.summary.confirmed >= 5, `expected findings, got ${result.summary.confirmed}`);
    assert.ok(result.summary.providers.includes("openai"));
    assert.ok(result.coverage.files_read > 0);
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

test("coverage states what was not running", { skip: !available }, async () => {
  const engine = bridge();
  try {
    const coverage = (await getCoverage(engine, { path: fixtures })) as {
      network_sensor: string;
      runtime_coverage: Array<{ status: string }>;
    };
    assert.equal(coverage.network_sensor, "not running");
    assert.ok(coverage.runtime_coverage.every((r) => r.status === "not_instrumented"));
  } finally {
    await engine.close();
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

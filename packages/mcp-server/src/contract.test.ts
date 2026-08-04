// Whether the contract gate can fail.
//
// The gate itself is `contract-gate.ts` and it answers one question: does the
// surface this server serves match `schemas/mcp-tools.schema.json`. These tests
// answer the question underneath it, which is the one that went unasked for
// months: would anything have noticed if it did not.
//
// So each case takes the real derived surface, breaks it the way the four
// recorded deviations broke it, and asserts the contract rejects the result. A
// gate whose failure path is never exercised is a gate nobody has seen work.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";

import { buildSurface, describeInput, type ToolDescription, type ToolSurface } from "./contract/surface.js";
import { VALUE_DOMAINS, proveDomain, type ValueDomain } from "./contract/value-domains.js";
import { TOOLS } from "./registry.js";

function contractValidator(): ValidateFunction {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addSchema(
    JSON.parse(
      readFileSync(new URL("../../../schemas/finding.schema.json", import.meta.url), "utf8"),
    ) as object,
  );
  return ajv.compile(
    JSON.parse(
      readFileSync(new URL("../../../schemas/mcp-tools.schema.json", import.meta.url), "utf8"),
    ) as object,
  );
}

const validate = contractValidator();

/** A deep copy, so one case's damage never reaches the next. */
function damaged(surface: ToolSurface, change: (copy: ToolSurface) => void): ToolSurface {
  const copy = JSON.parse(JSON.stringify(surface)) as ToolSurface;
  change(copy);
  return copy;
}

function rejects(surface: ToolSurface, because: string): void {
  const valid = validate(surface);
  assert.equal(
    valid,
    false,
    `the contract accepted a surface it must refuse (${because}). A gate that passes here would ` +
      `have let the deviation it was written for through.`,
  );
}

test("the served tool surface matches the contract", async () => {
  const surface = await buildSurface();
  const valid = validate(surface);
  assert.equal(
    valid,
    true,
    `the tool surface disagrees with schemas/mcp-tools.schema.json:\n${JSON.stringify(validate.errors, null, 2)}`,
  );
});

test("a tool the contract does not name is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      // The whole reason the contract listed seven tools while four were served.
      const scan = copy.tools["scan_project"];
      assert.ok(scan);
      (copy.tools as Record<string, ToolDescription>)["explain_finding"] = scan;
    }),
    "an unregistered tool name appeared",
  );
});

test("a tool the contract names and the server drops is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      delete (copy.tools as Record<string, unknown>)["trace_reconciliation"];
    }),
    "a contracted tool stopped being served",
  );
});

test("an argument the contract does not define is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      const scan = copy.tools["scan_project"];
      assert.ok(scan);
      (scan.input as Record<string, unknown>)["confidence"] = { type: "string", required: false };
    }),
    "the flat confidence argument came back beside the nested one",
  );
});

test("an argument whose type moved is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      const scan = copy.tools["scan_project"];
      assert.ok(scan);
      // An opaque token where the contract states an integer offset. This is the
      // pagination deviation, in the direction it would actually be made.
      (scan.input as Record<string, unknown>)["cursor"] = { type: "string", required: false };
    }),
    "cursor changed from an integer offset to a string",
  );
});

test("a response field the contract names and the answer drops is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      const scan = copy.tools["scan_project"];
      assert.ok(scan);
      const summary = (scan.response as Record<string, Record<string, unknown>>)["summary"];
      assert.ok(summary);
      delete summary["by_provider"];
    }),
    "summary.by_provider disappeared from the answer",
  );
});

test("a per provider count pooled back into one integer is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      const scan = copy.tools["scan_project"];
      assert.ok(scan);
      const summary = (scan.response as Record<string, Record<string, unknown>>)["summary"];
      assert.ok(summary);
      // The exact shape the contract used to carry. One integer merges what the
      // engine proved with what it could not rule out, which CLAUDE.md forbids.
      summary["by_provider"] = { openai: 120 };
    }),
    "by_provider went back to one integer per provider",
  );
});

test("a runtime_hooks value outside the four states is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      const scan = copy.tools["scan_project"];
      assert.ok(scan);
      const coverage = (scan.response as Record<string, Record<string, unknown>>)["coverage"];
      assert.ok(coverage);
      // A boolean here was the original defect: false was published as the hooks
      // were not attached, for a report that had named no language at all.
      coverage["runtime_hooks"] = false;
    }),
    "runtime_hooks answered with a boolean",
  );
});

// The value set cases below are the ones the gate could not fail before. Every
// value in the document came from one reference report, that report said
// `reconciliation_mode: "full"`, and so `network_sensor` only ever answered
// `running`. Misspelling SENSOR_NOT_RUNNING left the gate green; the contract
// named three states and guarded one.

test("a sensor state that stops being spelled the way the contract spells it is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      const domain = copy.value_domains["network_sensor"];
      assert.ok(domain);
      // Exactly the damage that went through green: the state the report never
      // reached, broken into a spelling no client compares equal to.
      domain.values = domain.values.map((value) => (value === "not_running" ? "not running" : value));
    }),
    "not_running lost its spelling in a document that never produced it",
  );
});

test("a sensor state that stops being produced at all is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      const domain = copy.value_domains["network_sensor"];
      assert.ok(domain);
      // A server that answers no where it used to answer unknown makes a claim
      // about the machine out of its own ignorance. Dropping the state is how
      // that ships, and the contract has to refuse the smaller set.
      domain.values = domain.values.filter((value) => value !== "unknown");
    }),
    "the sensor lost a state and the contract still names three",
  );
});

test("a hook state folded into another is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      const domain = copy.value_domains["runtime_hooks"];
      assert.ok(domain);
      // Folding degraded into instrumented claims coverage the report did not.
      domain.values = domain.values.filter((value) => value !== "degraded");
    }),
    "degraded stopped being one of the four hook states",
  );
});

test("an answer field that stops carrying a guarded value is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      const domain = copy.value_domains["network_sensor"];
      assert.ok(domain);
      domain.fields = domain.fields.filter(
        (field) => field !== "scan_project.response.coverage.network_sensor",
      );
    }),
    "a domain quietly stopped guarding one of the two answers that carry the value",
  );
});

test("a value set the producer cannot reach stops the gate", () => {
  const sensor = VALUE_DOMAINS.find((domain) => domain.name === "network_sensor");
  assert.ok(sensor);
  const overclaimed: ValueDomain = { ...sensor, values: [...sensor.values, "suspended"] };
  // A set written into the contract and produced by nothing is the failure this
  // whole mechanism exists to end: the gate would report the field as guarded
  // and the value would be guarded by no code at all.
  assert.throws(
    () => proveDomain(overclaimed, {}),
    /no probe reaches/,
    "a declared value nothing produces was accepted into the document",
  );
});

test("a value the producer reaches and the set does not name stops the gate", () => {
  const hooks = VALUE_DOMAINS.find((domain) => domain.name === "runtime_hooks");
  assert.ok(hooks);
  const understated: ValueDomain = {
    ...hooks,
    values: hooks.values.filter((value) => value !== "degraded"),
  };
  assert.throws(
    () => proveDomain(understated, {}),
    /which its value set does not name/,
    "a state the code can answer with was left out of the contract's set in silence",
  );
});

test("a domain guarding a field the answers no longer carry stops the gate", async () => {
  const surface = await buildSurface();
  const sensor = VALUE_DOMAINS.find((domain) => domain.name === "network_sensor");
  assert.ok(sensor);
  const renamed: ValueDomain = {
    ...sensor,
    fields: ["scan_project.response.coverage.sensor"],
  };
  // Without this the domain would keep proving its values while guarding a path
  // nothing serves, which reads as coverage and is not.
  assert.throws(
    () => proveDomain(renamed, surface.tools),
    /carries no string there/,
    "a domain went on claiming a response field that had been renamed away",
  );
});

test("every domain guards at least one field a caller actually sees", async () => {
  const surface = await buildSurface();
  for (const domain of VALUE_DOMAINS) {
    assert.ok(
      domain.fields.length > 0,
      `${domain.name} proves values that reach no answer, which proves nothing about the surface`,
    );
    for (const field of domain.fields) {
      const proven = surface.value_domains[domain.name];
      assert.ok(proven, `${domain.name} is declared and never derived`);
      assert.ok(
        proven.fields.includes(field),
        `${domain.name} declares ${field} and the derived document does not carry it`,
      );
    }
  }
});

test("an empty join path where the contract states null is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      const trace = copy.tools["trace_reconciliation"];
      assert.ok(trace);
      const step = (trace.response as Record<string, unknown[]>)["join_path"]?.[0];
      assert.ok(step);
      delete (step as Record<string, unknown>)["outcome"];
    }),
    "a join step stopped saying whether the match was made",
  );
});

test("an error code outside the contract's table is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      copy.error_codes.push("REPORT_UNREADABLE");
      copy.error_codes.sort();
    }),
    "a code was invented in the server and never written into the table",
  );
});

test("a code the contract expects and the server stops producing is refused", async () => {
  const surface = await buildSurface();
  rejects(
    damaged(surface, (copy) => {
      copy.error_codes = copy.error_codes.filter((code) => code !== "TRACE_UNSUPPORTED");
    }),
    "a tool stopped refusing and the contract still says it does",
  );
});

test("a zod type the describer has not been taught stops the gate", async () => {
  const { z } = await import("zod");
  // An array argument is legitimate; the contract names filter.provider as one.
  // What matters is that an undescribed type is refused rather than dropped: a
  // dropped argument is one the contract cannot check while the gate is green.
  assert.throws(
    () => describeInput(z.object({ provider: z.array(z.string()) })),
    /cannot state as a contract field/,
    "an unmapped zod type was left out of the document instead of stopping it",
  );
});

test("every registered tool declares how it answers and how it refuses", () => {
  assert.ok(TOOLS.length > 0, "no tools are registered, so the gate compares nothing");
  for (const tool of TOOLS) {
    assert.ok(
      tool.referenceFailures.length > 0,
      `${tool.name} declares no failing call, so its error code never reaches the contract`,
    );
  }
});

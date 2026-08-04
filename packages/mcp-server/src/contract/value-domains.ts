// Closed value sets, proven one value at a time.
//
// The gate derived its whole document from one reference report, and that is the
// right shape of evidence for a response and the wrong one for an enum. A single
// report drives each producing function down exactly one branch: that report says
// `reconciliation_mode: "full"`, so `network_sensor` answered `running` and the
// document never carried `not_running` or `unknown` at all. The contract then
// checked one value against a three value enum and passed. Spelling
// `SENSOR_NOT_RUNNING` with a space in it left the gate green; only breaking
// `SENSOR_RUNNING` turned it red. A contract saying "this field's values are
// these three" was in practice saying "one of this field's values is this one".
//
// So the two questions are separated here.
//
//   The shape of an answer stays sampled. A shape is what a whole handler
//   produces over a whole report, and only running that handler can produce one;
//   `reference-report.ts` is the input it runs over.
//
//   The value set of a field comes from the function that produces the value.
//   Growing the fixture set instead would need one report per value per field,
//   which is twelve reports for the two fields below and multiplies again with
//   every field added, each one held valid against finding.schema.json by hand.
//   The fixtures would drift from the states they were written to reach, and a
//   fixture that no longer reaches its state is a value silently back out of the
//   document: the same failure one directory along.
//
// A value set copied out of the constants would be weaker than it looks. It would
// prove the constants and say nothing about whether the code can reach them, so
// deleting the `MODES_WITHOUT_WIRE` branch from `networkSensor` would leave the
// declared set intact while the server lost a state. So each domain names its
// producer and the inputs that drive it into each state, this module runs them,
// and the produced set must equal the declared set in both directions. A declared
// value no probe reaches and a produced value nothing declared are both errors,
// and both stop the gate rather than shrinking the document.

import type { Coverage } from "../report.js";
import {
  HOOKS_DEGRADED,
  HOOKS_INSTRUMENTED,
  HOOKS_NOT_INSTRUMENTED,
  SENSOR_NOT_RUNNING,
  SENSOR_RUNNING,
  UNKNOWN,
  networkSensor,
  runtimeHooks,
} from "../sources.js";
import type { ToolDescription } from "./surface.js";

/** One input, and the state it exists to drive the producer into. */
export interface Probe {
  /** What this input is, in the report's terms. Quoted when a probe misfires. */
  readonly why: string;
  readonly coverage: Coverage;
}

/** A field whose accepted values the contract closes. */
export interface ValueDomain {
  /** The field name, as the contract and the answers both spell it. */
  readonly name: string;
  /**
   * Every value the producer may return, from the exported constants rather than
   * from string literals: a constant renamed in one place and not the other is
   * then a compile error instead of a quiet difference between two lists.
   *
   * Declaration order, matching the contract's enum, for the reason `surface.ts`
   * gives for input enums: the order is part of what the contract names.
   */
  readonly values: readonly string[];
  /**
   * Where this value reaches a caller, as paths into the derived document.
   *
   * Declared so the gate can say what it protects, and checked so the claim
   * cannot go stale: a response field that is renamed stops resolving here and
   * the gate fails, rather than the domain quietly guarding nothing.
   */
  readonly fields: readonly string[];
  /** Contract pointers this domain proves. Reported, and checked for staleness. */
  readonly contractSites: readonly string[];
  /** The function under test. The document is derived by running it. */
  produce(coverage: Coverage): string;
  /** One per declared value, at least. Fewer is a value nothing proves. */
  readonly probes: readonly Probe[];
}

/** A coverage statement carrying only what a probe is about. */
function coverageWith(fields: Partial<Coverage>): Coverage {
  // The three required fields are noise for every probe here and are given
  // values that claim nothing: no probe below reads them, and a producer that
  // started reading them would be answering a different question.
  return { parsed_files: 0, unparsed_files: [], undetected_libraries: [], ...fields };
}

/**
 * The domains this gate proves.
 *
 * Both are reductions this server computes rather than passes through, which is
 * what makes them checkable here: a field the engine writes and this server
 * copies has its producer in the Rust workspace, and a probe against it would
 * prove this module's own fixture instead of the code that answers.
 */
export const VALUE_DOMAINS: readonly ValueDomain[] = [
  {
    name: "network_sensor",
    values: [SENSOR_RUNNING, SENSOR_NOT_RUNNING, UNKNOWN],
    fields: [
      "get_coverage_report.response.network_sensor",
      "scan_project.response.coverage.network_sensor",
    ],
    contractSites: [
      "/$defs/coverageResponse/properties/network_sensor",
      "/$defs/scanResponse/properties/coverage/properties/network_sensor",
    ],
    produce: networkSensor,
    probes: [
      {
        why: "a mode whose source list includes the wire",
        coverage: coverageWith({ reconciliation_mode: "full" }),
      },
      {
        why: "a second such mode, so the answer does not rest on one spelling",
        coverage: coverageWith({ reconciliation_mode: "static_plus_wire" }),
      },
      {
        why: "a mode that names its sources and the wire is not among them",
        coverage: coverageWith({ reconciliation_mode: "static_only" }),
      },
      {
        why: "a second such mode",
        coverage: coverageWith({ reconciliation_mode: "static_plus_runtime" }),
      },
      {
        why: "a report older than the field, which has said nothing either way",
        coverage: coverageWith({}),
      },
      {
        why: "a mode this server has not been taught, which may or may not include the wire",
        coverage: coverageWith({ reconciliation_mode: "static_plus_telemetry" }),
      },
    ],
  },

  {
    name: "runtime_hooks",
    values: [HOOKS_INSTRUMENTED, HOOKS_DEGRADED, HOOKS_NOT_INSTRUMENTED, UNKNOWN],
    fields: ["scan_project.response.coverage.runtime_hooks"],
    contractSites: ["/$defs/scanResponse/properties/coverage/properties/runtime_hooks"],
    produce: runtimeHooks,
    probes: [
      {
        why: "one language hooked, alongside one that is not",
        coverage: coverageWith({
          runtime_coverage: [
            { language: "python", status: "instrumented" },
            { language: "go", status: "not_instrumented" },
          ],
        }),
      },
      {
        why: "a hook in place and partial, with nothing fully covered",
        coverage: coverageWith({ runtime_coverage: [{ language: "node", status: "degraded" }] }),
      },
      {
        why: "every language the report named says no hook ran",
        coverage: coverageWith({
          runtime_coverage: [
            { language: "python", status: "not_instrumented" },
            { language: "ruby", status: "unsupported" },
          ],
        }),
      },
      {
        why: "a report that named no language, which has said nothing about hooks",
        coverage: coverageWith({ runtime_coverage: [] }),
      },
      {
        why: "a report older than the field",
        coverage: coverageWith({}),
      },
      {
        why: "a status this server has not been taught, which is not the same as no hook",
        coverage: coverageWith({ runtime_coverage: [{ language: "rust", status: "partial" }] }),
      },
    ],
  },
];

/** A domain as the derived document states it. */
export interface ProvenDomain {
  /** The produced set, in the contract's order. */
  values: string[];
  /** The answer fields it governs, sorted so two runs serialise alike. */
  fields: string[];
}

/** Reads a dotted path out of the derived document, or says it is not there. */
function valueAt(tools: Readonly<Record<string, ToolDescription>>, path: string): unknown {
  const [toolName, ...rest] = path.split(".");
  const tool = toolName === undefined ? undefined : tools[toolName];
  if (tool === undefined) return undefined;

  let node: unknown = tool;
  for (const step of rest) {
    if (typeof node !== "object" || node === null) return undefined;
    node = (node as Record<string, unknown>)[step];
  }
  return node;
}

/**
 * Runs one domain's probes and checks the answer against its declared set.
 *
 * Exported so a test can hand it a domain that is wrong on purpose. A gate whose
 * failure path is never exercised is a gate nobody has seen work, and this one
 * exists because a check that could not fail read as a check that passed.
 */
export function proveDomain(
  domain: ValueDomain,
  tools: Readonly<Record<string, ToolDescription>>,
): ProvenDomain {
  const produced = new Set(domain.probes.map((probe) => domain.produce(probe.coverage)));

  const unreachable = domain.values.filter((value) => !produced.has(value));
  if (unreachable.length > 0) {
    throw new Error(
      `${domain.name} names ${unreachable.join(", ")} in its value set and no probe reaches ` +
        `${unreachable.length === 1 ? "it" : "them"}. Either the producer lost a branch or the ` +
        `probes stopped covering one; a value written into the contract and never produced is a ` +
        `state the gate reports as guarded and does not guard.`,
    );
  }

  const undeclared = [...produced].filter((value) => !domain.values.includes(value));
  if (undeclared.length > 0) {
    throw new Error(
      `${domain.name} produced ${undeclared.join(", ")}, which its value set does not name. The ` +
        `set is the contract's, so a new state has to be written there before it can reach a ` +
        `caller.`,
    );
  }

  if (domain.fields.length === 0) {
    throw new Error(
      `${domain.name} guards no answer field, so proving its values says nothing about what this ` +
        `server serves`,
    );
  }

  for (const field of domain.fields) {
    const served = valueAt(tools, field);
    if (typeof served !== "string") {
      throw new Error(
        `${domain.name} claims to guard ${field}, and the derived document carries no string ` +
          `there. A renamed or dropped response field would otherwise leave the domain guarding ` +
          `nothing while the gate still reported it as covered.`,
      );
    }
    if (!produced.has(served)) {
      throw new Error(
        `${field} answered ${served}, which ${domain.name} cannot produce. One of the two is ` +
          `reading a different source than the other.`,
      );
    }
  }

  return { values: [...domain.values], fields: [...domain.fields].sort() };
}

/**
 * Every domain, keyed by field name.
 *
 * Sorted for the reason the rest of the document is: it is compared byte for byte
 * and read by a person in review.
 */
export function proveValueDomains(
  tools: Readonly<Record<string, ToolDescription>>,
): Record<string, ProvenDomain> {
  if (VALUE_DOMAINS.length === 0) {
    // A gate with nothing to check must fail rather than pass (CLAUDE.md O6b).
    throw new Error("no value domains are declared, so no field's value set is being checked");
  }

  const rows = VALUE_DOMAINS.map(
    (domain) => [domain.name, proveDomain(domain, tools)] as const,
  ).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  return Object.fromEntries(rows);
}

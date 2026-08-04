// The tools this server publishes, in one list.
//
// The list exists because of what went unnoticed without it. Four deviations
// between `docs/04-contracts/mcp-tools.md` and this package survived for months:
// a flat `confidence` argument where the contract nests it, one integer per
// provider where the contract now splits it, `summary.confirmed` where the
// contract said `by_confidence`, an integer cursor where the contract said an
// opaque one. Every one of them was found by a human reading two files side by
// side, because nothing compared them.
//
// A gate that compares them needs one thing this package did not have: a
// description of the surface produced by the code rather than written beside it.
// A second hand written list would be a fourth place to drift.
//
// So registration goes through here. `index.ts` iterates this array and serves
// what it finds, and `surface.ts` reads the same array to derive the document
// the contract is checked against. A tool that is not in this array is not
// served, and a tool that is in it cannot be missing from the document.
//
// Each entry also names the calls the surface is derived over: one that succeeds
// and at least one that is refused. Both are required by the type, so a new tool
// cannot be added without saying how it answers and how it says no.

import { z } from "zod";

import type { ReportSource } from "./bridge.js";
import { traceInput, traceReconciliation } from "./reconciliation.js";
import { coverageInput, detailInput, getCoverage, getDetail, runScan, scanInput } from "./tools.js";

/** Identifiers from `reference-report.ts`, named so the calls below read. */
const DECLARED_FINDING = "fnd_7c1e4a90b3d25f61";
const RECONCILED_FINDING = "fnd_2b64c1d70e9a3f85";
const NO_SUCH_FINDING = "fnd_0000000000000000";

/** A call the surface document is derived over. */
export interface ReferenceCall {
  /** Arguments as a caller sends them, before the tool's own schema parses them. */
  readonly args: unknown;
  /**
   * What the engine answers.
   *
   * Named rather than supplied so this module carries no fixture: the report
   * lives in `reference-report.ts` and the gate resolves the name against it.
   * `unreadable` is an answer that is not a scan report at all, which is the one
   * engine failure every tool has to turn into the shared error envelope.
   */
  readonly engine: "report" | "unreadable";
}

export interface ToolRegistration {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  /** The zod object `index.ts` registers and `surface.ts` describes. */
  readonly inputSchema: z.ZodObject<z.ZodRawShape>;
  /** Parses `args` with `inputSchema`, then answers. */
  run(bridge: ReportSource, args: unknown): Promise<Record<string, unknown>>;
  readonly reference: ReferenceCall;
  /** How this tool refuses. At least one, so every error code reaches the gate. */
  readonly referenceFailures: readonly ReferenceCall[];
}

/**
 * Ties a tool's schema to its handler where both are written.
 *
 * The generic is what makes `run` type check against the schema it is declared
 * with: a handler reading `input.limit` off a schema that has no `limit` fails
 * to compile here rather than at run time in somebody's editor.
 */
function defineTool<Shape extends z.ZodRawShape>(tool: {
  name: string;
  title: string;
  description: string;
  inputSchema: z.ZodObject<Shape>;
  run(bridge: ReportSource, input: z.infer<z.ZodObject<Shape>>): Promise<Record<string, unknown>>;
  reference: ReferenceCall;
  referenceFailures: readonly ReferenceCall[];
}): ToolRegistration {
  return {
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: tool.inputSchema as unknown as z.ZodObject<z.ZodRawShape>,
    run: (bridge, args) => tool.run(bridge, tool.inputSchema.parse(args)),
    reference: tool.reference,
    referenceFailures: tool.referenceFailures,
  };
}

export const TOOLS: readonly ToolRegistration[] = [
  defineTool({
    name: "scan_project",
    title: "Scan a project for model provider egress",
    description:
      "Walks a project and reports call sites that send data to an LLM provider. " +
      "Returns a summary with a first page of findings, plus what the scan could not read. " +
      "A result with no findings is not the same as a project with no egress; read the coverage block. " +
      "summary.reconciliation_mode says which sources fed the run, and every count is only as " +
      "strong as that; summary.unmatched_wire_traffic counts findings where data left the machine " +
      "and no code explains it, and is null when the findings do not state their kind. " +
      "Confirmed and suspected findings are two separate lists and are never merged: one call " +
      "pages one of them, filter.confidence chooses which, and page.other says how many " +
      "are in the other. summary.by_provider counts findings per provider and keeps that " +
      "same split, so a provider seen only in suspected findings is still named. " +
      "On a project with no runtime hooks installed the unmatched wire " +
      "findings are suspected, so a caller that never asks for that list never sees them. " +
      "coverage.runtime_hooks is one of instrumented, degraded, not_instrumented or unknown, " +
      "and unknown means the report named no language rather than that no hook ran. " +
      "coverage_note is null unless something in the answer cannot be read at face value, " +
      "such as a report that puts a finding in one list and labels it as the other.",
    inputSchema: scanInput,
    run: runScan,
    reference: { args: { path: ".", limit: 2 }, engine: "report" },
    referenceFailures: [{ args: { path: "." }, engine: "unreadable" }],
  }),

  defineTool({
    name: "get_finding_detail",
    title: "Full record for one finding",
    description:
      "Returns the complete finding, including its evidence and the rule that produced it. " +
      "Use after scan_project, with an identifier from that result.",
    inputSchema: detailInput,
    run: getDetail,
    reference: { args: { path: ".", finding_id: DECLARED_FINDING }, engine: "report" },
    referenceFailures: [
      { args: { path: ".", finding_id: NO_SUCH_FINDING }, engine: "report" },
      { args: { path: ".", finding_id: DECLARED_FINDING }, engine: "unreadable" },
    ],
  }),

  defineTool({
    name: "get_coverage_report",
    title: "What the scan could not see",
    description:
      "Files that could not be read, libraries with no detector, and which observation " +
      "layers were running. Answers whether a clean scan means clean or means unread. " +
      "network_sensor is one of running, not_running or unknown, and the third means the " +
      "report did not say rather than that nothing was watching. flow_buckets counts the " +
      "observed flows that produced no finding, next to in_scope_flows, the count they are " +
      "read against; a bucket without that denominator states no proportion, and none of " +
      "them is readable away from the sensor state.",
    inputSchema: coverageInput,
    run: getCoverage,
    reference: { args: { path: "." }, engine: "report" },
    referenceFailures: [{ args: { path: "." }, engine: "unreadable" }],
  }),

  defineTool({
    name: "trace_reconciliation",
    title: "Where a derived finding came from",
    description:
      "Returns the join steps, the contributing sources and the difference behind a finding " +
      "whose source is reconciled. Use when a finding says the code and the run disagree and " +
      "you need to see what tied the two together. Declared and observed findings have no " +
      "reconciliation trace; get_finding_detail is what covers those. join_path and " +
      "contributing_sources are null, never empty, when the finding carried nothing to read " +
      "them from: a reconciled finding always rests on at least two records, so an empty list " +
      "would state something that cannot be true, and coverage_note says what was missing.",
    inputSchema: traceInput,
    run: traceReconciliation,
    reference: { args: { path: ".", finding_id: RECONCILED_FINDING }, engine: "report" },
    referenceFailures: [
      // Out of range depth, checked in the handler so the caller gets the
      // contract's envelope rather than a schema exception.
      { args: { path: ".", finding_id: RECONCILED_FINDING, max_depth: 0 }, engine: "report" },
      // A finding that was read from somewhere rather than derived. There is no
      // reconciliation graph under it, which is a refusal and not a fault.
      { args: { path: ".", finding_id: DECLARED_FINDING }, engine: "report" },
      { args: { path: ".", finding_id: NO_SUCH_FINDING }, engine: "report" },
    ],
  }),
];

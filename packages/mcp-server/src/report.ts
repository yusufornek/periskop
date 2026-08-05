// The engine's answer, checked before anything reads it.
//
// `zod` validates what the caller sends in. Nothing validated what the engine
// sends back, and `as ScanReport` is not a check: it tells the compiler to stop
// asking and changes no value at run time. So an answer such as
// `{ "result": "ok" }`, or one whose findings list came back null, travelled
// intact into the projection and failed there with a TypeError. The caller got a
// crash naming a line in this server instead of the contract's error envelope
// naming the answer that caused it.
//
// The shape is therefore declared once, as a schema, and the types are read off
// it. Declaring it twice, as a schema and again as an interface, is how the two
// drift apart, and they drift precisely where the check was supposed to hold.
//
// What is optional here is deliberate rather than lax. The report contract
// requires most of these fields, but an engine older than a field omits it, and
// requiring it here would turn that into a rejected report rather than an
// unknown in the answer. Every reader of an optional field follows the same
// rule: absent is not zero and it is not no.

import { z } from "zod";

import type { ReportSource } from "./bridge.js";

const entityRef = z.object({
  ref_type: z.string(),
  ref_id: z.string(),
});
export type EntityRef = z.infer<typeof entityRef>;

const evidence = z.object({
  evidence_type: z.string(),
  ref: z.string(),
});
export type Evidence = z.infer<typeof evidence>;

const finding = z.object({
  finding_id: z.string(),
  provider_ref: z.string(),
  confidence: z.string(),
  detector: z.object({ rule_id: z.string() }),
  location: z
    .object({
      path: z.string().optional(),
      span: z.object({ start_line: z.number() }).optional(),
    })
    .optional(),
  // Read by the reconciliation trace rather than by the scan projection, and
  // optional for the reason the module comment gives: an engine older than the
  // field omits it, and a required field would turn that into a rejected report
  // instead of a coverage note in the answer.
  kind: z.string().optional(),
  source: z.string().optional(),
  refs: z.array(entityRef).optional(),
  evidence: z.array(evidence).optional(),
  data_sources: z
    .array(z.object({ source: z.string(), detector_id: z.string().nullable().optional() }))
    .optional(),
});
export type Finding = z.infer<typeof finding>;

const coverage = z.object({
  parsed_files: z.number(),
  unparsed_files: z.array(z.object({ path: z.string(), reason: z.string() })),
  undetected_libraries: z.array(z.string()),
  // Optional, and that is the whole point of the field's three states: a report
  // that names no language has said nothing about hooks, which is not the same
  // claim as no hook having run. What each status means is in sources.ts, the
  // only reader.
  runtime_coverage: z.array(z.object({ language: z.string(), status: z.string() })).optional(),
  // The observation half of the statement, optional for the same reason.
  reconciliation_mode: z.string().optional(),
  // Named here and read nowhere, on purpose. It looks like the direct answer to
  // whether a network sensor ran and it is not, for the reason `networkSensor`
  // gives; declaring it keeps that trap visible and lets a test prove the answer
  // does not come from it.
  sensor_platform_class: z.string().optional(),
  // Which detector set decided the run (coverage-statement.schema.json 1.2).
  // Optional here and required in the tool surface: an engine older than the
  // field sends nothing, and a boundary that rejected the whole report over it
  // would turn a missing field into no answer at all. The tool response is
  // where it becomes mandatory, because that is a document this server writes
  // rather than one it receives.
  rule_set_source: z.enum(["embedded", "directory"]).optional(),
  in_scope_flows: z.number().optional(),
  out_of_scope_flows: z.number().optional(),
  known_benign_flows: z.number().optional(),
  unattributed_flows: z.number().optional(),
  unclassified_flows: z.number().optional(),
});
export type Coverage = z.infer<typeof coverage>;

const scanReport = z.object({
  report_id: z.string(),
  scan_run_id: z.string(),
  verdict: z.string(),
  findings: z.array(finding),
  suspect_findings: z.array(finding),
  coverage,
});
export type ScanReport = z.infer<typeof scanReport>;

/** A report, or the reason the answer could not be read as one. */
export type ReportRead = { ok: true; report: ScanReport } | { ok: false; problem: string };

/** How many of a failed check's complaints travel with the failure. */
const QUOTED_ISSUES = 3;

/**
 * What was wrong with the answer, in the reader's terms rather than zod's.
 *
 * Bounded, because a malformed report can produce one complaint per finding and
 * the whole list would be the error message. The count of what was left out
 * stays, so a short explanation is not read as the complete one.
 */
function explain(error: z.ZodError): string {
  const issues = error.issues.slice(0, QUOTED_ISSUES).map((issue) => {
    const where = issue.path.length > 0 ? issue.path.join(".") : "the answer itself";
    return `${where}: ${issue.message}`;
  });
  const rest = error.issues.length - issues.length;
  if (rest > 0) issues.push(`and ${rest} further problem${rest === 1 ? "" : "s"}`);
  return issues.join("; ");
}

/**
 * Asks the engine for a scan and checks that what came back is one.
 *
 * One place rather than one per tool: four handlers asked the same question and
 * each of them promised the compiler the same unverified thing.
 */
export async function fetchReport(bridge: ReportSource, path: string): Promise<ReportRead> {
  const answer = await bridge.call("scan", { path });
  const checked = scanReport.safeParse(answer);
  if (!checked.success) return { ok: false, problem: explain(checked.error) };

  // The engine's own object, not zod's copy of it. The copy carries only the
  // fields this schema names, and get_finding_detail returns the whole finding:
  // every field the engine sends and this server does not model would be dropped
  // on the way out, which is the silent loss the check exists to prevent. The
  // assertion is what the check above just established.
  return { ok: true, report: answer as ScanReport };
}

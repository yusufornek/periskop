// Tool surface.
//
// Two rules shape everything here.
//
// Summary first. A scan of a real repository can produce hundreds of findings,
// and returning all of them puts the entire result into the model's context in
// one shot, leaving no room for the conversation that was supposed to follow.
// So the first call returns counts and a page, and detail is fetched for what
// the reader actually asks about.
//
// Facts, not prose. These tools return structured evidence. They do not generate
// explanations, because a tool whose output changes wording between runs cannot
// be diffed, cached or audited. Interpretation is the model's job; establishing
// what is true is the engine's.

import { z } from "zod";

import type { ReportSource } from "./bridge.js";
import {
  countUnmatchedWireTraffic,
  flowBuckets,
  networkSensor,
  reconciliationMode,
} from "./sources.js";

export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;

/**
 * The two lists a report keeps, named by the confidence they carry.
 *
 * They are separate lists rather than one list with a field because the
 * difference is what a reader has to act on: a confirmed finding is something
 * the engine proved, a suspected one is something it could not rule out. The
 * words are the ones `findings-schema.md` uses and the ones `mcp-tools.md`
 * gives `filter.confidence`, so the tool argument, the report and the finding
 * record all spell the same state the same way.
 */
export const CONFIDENCE_LEVELS = ["confirmed", "suspect"] as const;
export type ConfidenceLevel = (typeof CONFIDENCE_LEVELS)[number];

export interface EntityRef {
  ref_type: string;
  ref_id: string;
}

export interface Evidence {
  evidence_type: string;
  ref: string;
}

export interface Finding {
  finding_id: string;
  provider_ref: string;
  confidence: string;
  detector: { rule_id: string };
  location?: { path?: string; span?: { start_line: number } };
  // Read by the reconciliation trace rather than by the scan projection, and
  // optional here for one reason: an engine older than the field would omit it,
  // and a required field would turn that into a type error at the boundary
  // instead of a coverage note in the answer.
  kind?: string;
  source?: string;
  refs?: EntityRef[];
  evidence?: Evidence[];
  data_sources?: Array<{ source: string; detector_id?: string | null }>;
}

export interface Coverage {
  parsed_files: number;
  unparsed_files: Array<{ path: string; reason: string }>;
  undetected_libraries: string[];
  runtime_coverage: Array<{ language: string; status: string }>;
  // The observation half of the statement, optional for the same reason
  // Finding.kind is: an engine older than a field omits it, and requiring it
  // here would turn that into a type error at the boundary instead of an
  // unknown in the answer. What each one means is in sources.ts, which is the
  // only reader.
  reconciliation_mode?: string;
  in_scope_flows?: number;
  out_of_scope_flows?: number;
  known_benign_flows?: number;
  unattributed_flows?: number;
  unclassified_flows?: number;
}

export interface ScanReport {
  report_id: string;
  scan_run_id: string;
  verdict: string;
  findings: Finding[];
  suspect_findings: Finding[];
  coverage: Coverage;
}

/**
 * Which findings this call is about.
 *
 * Nested rather than a flat argument, as `mcp-tools.md` §1 writes it. The
 * contract names three filters on this tool and only one of them is built, so a
 * flat argument would have to be renamed the day the second arrives; the object
 * takes a new key instead of a new signature.
 */
const scanFilter = z.object({
  confidence: z
    .enum(CONFIDENCE_LEVELS)
    .optional()
    .describe(
      "Which of the two finding lists to page: confirmed, or suspect. Defaults to confirmed. " +
        "The lists are never merged, and every answer says how many findings are in the one " +
        "it is not showing.",
    ),
});

export const scanInput = z.object({
  path: z.string().describe("Project directory to scan."),
  filter: scanFilter.optional().describe("Which findings to page. Defaults to the confirmed list."),
  limit: z
    .number()
    .int()
    .min(1)
    .max(MAX_PAGE_SIZE)
    .optional()
    .describe(`Findings to include in this page. Defaults to ${DEFAULT_PAGE_SIZE}.`),
  cursor: z.number().int().min(0).optional().describe("Offset from a previous page."),
});

export const detailInput = z.object({
  path: z.string().describe("Project directory the finding came from."),
  finding_id: z.string().describe("Identifier from a previous scan."),
});

export const coverageInput = z.object({
  path: z.string().describe("Project directory to report coverage for."),
});

/** One line per finding, enough to decide whether to ask for more. */
function condense(finding: Finding): Record<string, unknown> {
  return {
    finding_id: finding.finding_id,
    provider: finding.provider_ref,
    confidence: finding.confidence,
    rule_id: finding.detector.rule_id,
    location: finding.location?.path
      ? `${finding.location.path}:${finding.location.span?.start_line ?? 1}`
      : null,
  };
}

/** How many findings one provider accounts for, kept on the confidence axis. */
interface ProviderCount {
  confirmed: number;
  suspect: number;
}

/**
 * How many findings each provider accounts for.
 *
 * Counted over both lists, which is what keeps a provider that appears only in
 * suspected findings in the answer at all. Answered from the confirmed list
 * alone, such a provider vanished entirely and the project read as one that
 * talks to nobody.
 *
 * The count per provider is split rather than pooled. A single number would
 * merge what the engine proved with what it could not rule out, and those are
 * the two states a reader has to act on differently; pooling them here would
 * undo, inside one integer, the separation the two lists exist to keep.
 *
 * Keys are sorted by code unit so that two runs over the same report serialise
 * byte for byte.
 */
function byProvider(
  confirmed: readonly Finding[],
  suspect: readonly Finding[],
): Record<string, ProviderCount> {
  const counts = new Map<string, ProviderCount>();

  const tally = (findings: readonly Finding[], level: ConfidenceLevel): void => {
    for (const finding of findings) {
      const entry = counts.get(finding.provider_ref) ?? { confirmed: 0, suspect: 0 };
      entry[level] += 1;
      counts.set(finding.provider_ref, entry);
    }
  };
  tally(confirmed, "confirmed");
  tally(suspect, "suspect");

  return Object.fromEntries([...counts].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

export async function runScan(
  bridge: ReportSource,
  input: z.infer<typeof scanInput>,
): Promise<Record<string, unknown>> {
  const report = (await bridge.call("scan", { path: input.path })) as ScanReport;

  // Which list this page comes from. Paging only the confirmed list was the
  // bug: on a run without hooks every unmatched wire finding is suspected, so
  // the summary counted flows nothing explained, the page was empty, the total
  // was zero and no cursor reached them. The product's central claim was a
  // number the caller could not open.
  const shown: ConfidenceLevel = input.filter?.confidence ?? "confirmed";
  const paged = shown === "confirmed" ? report.findings : report.suspect_findings;
  const other: ConfidenceLevel = shown === "confirmed" ? "suspect" : "confirmed";
  const otherList = shown === "confirmed" ? report.suspect_findings : report.findings;

  const limit = input.limit ?? DEFAULT_PAGE_SIZE;
  const cursor = input.cursor ?? 0;
  const page = paged.slice(cursor, cursor + limit);
  const nextCursor = cursor + limit < paged.length ? cursor + limit : null;

  return {
    verdict: report.verdict,
    summary: {
      confirmed: report.findings.length,
      suspected: report.suspect_findings.length,
      // Both lists, because this is a kind and those two are confidences: a
      // suspected unmatched flow is still a flow nothing in the code explains.
      unmatched_wire_traffic: countUnmatchedWireTraffic([
        ...report.findings,
        ...report.suspect_findings,
      ]),
      // How many sources spoke. Without it a reader cannot weigh anything above:
      // a scan that only read code has said nothing about what left the machine,
      // and its silence has to be readable as silence.
      reconciliation_mode: reconciliationMode(report.coverage),
      // Counts per provider, the name and the question `mcp-tools.md` §1 gives
      // this field. A list of names could not answer it: one call site to a
      // provider and two hundred read identically, and weighing a scan starts
      // with which name carries the traffic. The value stays split by confidence
      // for the reason byProvider gives.
      by_provider: byProvider(report.findings, report.suspect_findings),
    },
    // Coverage travels with the summary rather than waiting to be asked for.
    // A caller who sees only counts would reasonably read zero findings as
    // nothing to find, which is a different claim.
    coverage: {
      files_read: report.coverage.parsed_files,
      files_unread: report.coverage.unparsed_files.length,
      libraries_without_rules: report.coverage.undetected_libraries,
      runtime_instrumented: report.coverage.runtime_coverage.some(
        (r) => r.status === "instrumented",
      ),
      // Read from the report, and named the same here as in the coverage tool so
      // that one fact does not answer to two words. It was a constant false
      // until the third source arrived, which was the wrong answer for every run
      // that had a sensor and an unprovable one for every run that did not.
      network_sensor: networkSensor(report.coverage),
    },
    findings: page.map(condense),
    page: {
      // Named, because an empty page carries no rows to infer it from and an
      // empty confirmed list is exactly when the other one matters.
      confidence: shown,
      cursor,
      limit,
      next_cursor: nextCursor,
      total: paged.length,
      // The list this answer is not showing, with the argument that pages it.
      // Structured rather than described, so that reaching the rest of the
      // findings does not depend on the caller having read the tool
      // description, and paged rather than inlined so that neither list can
      // empty the caller's context in one response.
      other: {
        confidence: other,
        total: otherList.length,
        fetch_with: { filter: { confidence: other } },
      },
    },
  };
}

export async function getDetail(
  bridge: ReportSource,
  input: z.infer<typeof detailInput>,
): Promise<Record<string, unknown>> {
  const report = (await bridge.call("scan", { path: input.path })) as ScanReport;
  const all = [...report.findings, ...report.suspect_findings];
  const finding = all.find((f) => f.finding_id === input.finding_id);

  if (!finding) {
    return {
      error: "no finding with that identifier in the current scan",
      finding_id: input.finding_id,
      // Identifiers are content addressed, so a stale one means the code moved
      // on rather than that the caller made a mistake. Saying which is which
      // saves a round of confusion.
      hint: "identifiers are derived from the call itself; rescan if the code changed",
    };
  }

  return { finding };
}

export async function getCoverage(
  bridge: ReportSource,
  input: z.infer<typeof coverageInput>,
): Promise<Record<string, unknown>> {
  const report = (await bridge.call("scan", { path: input.path })) as ScanReport;
  const coverage = report.coverage;

  return {
    files_read: coverage.parsed_files,
    unread: coverage.unparsed_files.slice(0, MAX_PAGE_SIZE),
    unread_total: coverage.unparsed_files.length,
    libraries_without_rules: coverage.undetected_libraries,
    runtime_coverage: coverage.runtime_coverage,
    // Which sources fed the run. The counters below say how much each source
    // could not account for, and none of them can be read without knowing
    // whether the source was there at all.
    reconciliation_mode: reconciliationMode(coverage),
    // Stated rather than implied. An empty list of network findings and an
    // absent network sensor look identical from the outside and mean opposite
    // things, and a sensor this server was told nothing about is a third case
    // that must not borrow the words of the second.
    network_sensor: networkSensor(coverage),
    // Counts, never lists, and never left out. These four hold flows that
    // produced no finding; a bucket that keeps traffic out of the count and
    // then disappears from the answer is a silent drop (K-15).
    flow_buckets: flowBuckets(coverage),
  };
}

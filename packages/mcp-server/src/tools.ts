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

import type { EngineBridge } from "./bridge.js";

export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;

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
}

export interface ScanReport {
  report_id: string;
  scan_run_id: string;
  verdict: string;
  findings: Finding[];
  suspect_findings: Finding[];
  coverage: Coverage;
}

export const scanInput = z.object({
  path: z.string().describe("Project directory to scan."),
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

export async function runScan(
  bridge: EngineBridge,
  input: z.infer<typeof scanInput>,
): Promise<Record<string, unknown>> {
  const report = (await bridge.call("scan", { path: input.path })) as ScanReport;

  const limit = input.limit ?? DEFAULT_PAGE_SIZE;
  const cursor = input.cursor ?? 0;
  const page = report.findings.slice(cursor, cursor + limit);
  const nextCursor = cursor + limit < report.findings.length ? cursor + limit : null;

  return {
    verdict: report.verdict,
    summary: {
      confirmed: report.findings.length,
      suspected: report.suspect_findings.length,
      providers: [...new Set(report.findings.map((f) => f.provider_ref))].sort(),
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
      network_observed: false,
    },
    findings: page.map(condense),
    page: { cursor, limit, next_cursor: nextCursor, total: report.findings.length },
  };
}

export async function getDetail(
  bridge: EngineBridge,
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
  bridge: EngineBridge,
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
    // Stated rather than implied. An empty list of network findings and an
    // absent network sensor look identical from the outside and mean opposite
    // things.
    network_sensor: "not running",
  };
}

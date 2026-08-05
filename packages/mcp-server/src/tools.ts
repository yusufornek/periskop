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
import { failure } from "./envelope.js";
import { fetchReport, type Finding } from "./report.js";
import {
  countUnmatchedWireTraffic,
  flowBuckets,
  networkSensor,
  reconciliationMode,
  runtimeHooks,
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

/**
 * The engine answered with something that is not a scan report.
 *
 * `CORE_UNAVAILABLE` from the contract's shared code table rather than a new
 * code, because that table is closed. What the caller has to be able to tell
 * apart is a scan that found nothing from a scan whose answer never arrived, and
 * an envelope says which one this is where a thrown TypeError did not.
 */
function unreadable(problem: string): Record<string, unknown> {
  return failure(
    "CORE_UNAVAILABLE",
    `the engine answered with something this server cannot read as a scan report: ${problem}`,
  );
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

/**
 * Where a finding is, as far as the report says and no further.
 *
 * The line was defaulted to 1, which is a location rather than the absence of
 * one: a finding with no span read as `src/app.py:1`, the reader opened the file
 * at the import block, found nothing that could have produced the finding and
 * concluded the detector was wrong. Nothing in the answer said the line was this
 * server's invention.
 *
 * So a path with no line states the path. It is what the report carries, it
 * claims nothing about where in the file, and it still gets the reader to the
 * right file. Null stays reserved for a finding that names no path at all, which
 * is the case where there is genuinely nothing to open.
 */
function locationOf(finding: Finding): string | null {
  const path = finding.location?.path;
  if (!path) return null;
  const line = finding.location?.span?.start_line;
  return line === undefined ? path : `${path}:${line}`;
}

/** One line per finding, enough to decide whether to ask for more. */
function condense(finding: Finding): Record<string, unknown> {
  return {
    finding_id: finding.finding_id,
    provider: finding.provider_ref,
    confidence: finding.confidence,
    rule_id: finding.detector.rule_id,
    location: locationOf(finding),
  };
}

/**
 * Findings in a list whose own confidence field is not the list's.
 *
 * The two lists and the per finding field say the same thing twice, and nothing
 * checked that they agree. They can disagree only if the report is wrong about
 * itself, which is exactly when a reader must not be handed either half as
 * settled: a suspected finding sitting in the confirmed list is paged under
 * `confidence: "confirmed"` and read as something the engine proved.
 */
function disagreeingRows(findings: readonly Finding[], level: ConfidenceLevel): number {
  return findings.filter((finding) => finding.confidence !== level).length;
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
  const read = await fetchReport(bridge, input.path);
  if (!read.ok) return unreadable(read.problem);
  const report = read.report;

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
  const disagreeing = disagreeingRows(paged, shown);

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
      // Three states rather than a boolean, for the reason `runtimeHooks` gives:
      // a report that listed no language answered false here, and false was
      // published as "the hooks were not attached".
      runtime_hooks: runtimeHooks(report.coverage),
      // Read from the report, and named the same here as in the coverage tool so
      // that one fact does not answer to two words. It was a constant false
      // until the third source arrived, which was the wrong answer for every run
      // that had a sensor and an unprovable one for every run that did not.
      network_sensor: networkSensor(report.coverage),
      // Which detectors decided this run: the set built into the binary, or a
      // directory somebody named. It belongs in the summary rather than only in
      // the full report because the summary is what most readers stop at, and a
      // narrower rule set produces a cleaner answer. Passed through from the
      // coverage statement; the path is deliberately not carried, there or here.
      rule_set_source: report.coverage.rule_set_source,
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
    // What this answer cannot be read at face value for, in the same field name
    // the trace tool uses. Never left empty when something is wrong with the
    // report, and never invented when nothing is: a note on every answer stops
    // being read.
    coverage_note:
      disagreeing > 0
        ? `${disagreeing} of the ${paged.length} findings in the ${shown} list state a different ` +
          `confidence of their own. The report puts a finding in one list and labels it as the ` +
          `other, so neither half can be taken as settled; the rows are returned as the engine ` +
          `sent them.`
        : null,
  };
}

export async function getDetail(
  bridge: ReportSource,
  input: z.infer<typeof detailInput>,
): Promise<Record<string, unknown>> {
  const read = await fetchReport(bridge, input.path);
  if (!read.ok) return unreadable(read.problem);
  const report = read.report;
  const all = [...report.findings, ...report.suspect_findings];
  const finding = all.find((f) => f.finding_id === input.finding_id);

  if (!finding) {
    // The contract's envelope, the same one the trace tool answers a stale
    // identifier with. Two shapes of error inside one tool, one an object and one
    // a bare string, is a caller writing two checks and forgetting the second.
    //
    // Identifiers are content addressed, so a stale one means the code moved on
    // rather than that the caller made a mistake. Saying which is which saves a
    // round of confusion.
    return failure(
      "FINDING_NOT_FOUND",
      `no finding with the identifier ${input.finding_id} in the current scan; identifiers are derived from the call itself, so rescan if the code changed`,
    );
  }

  return { finding };
}

export async function getCoverage(
  bridge: ReportSource,
  input: z.infer<typeof coverageInput>,
): Promise<Record<string, unknown>> {
  const read = await fetchReport(bridge, input.path);
  if (!read.ok) return unreadable(read.problem);
  const coverage = read.report.coverage;

  return {
    files_read: coverage.parsed_files,
    unread: coverage.unparsed_files.slice(0, MAX_PAGE_SIZE),
    unread_total: coverage.unparsed_files.length,
    libraries_without_rules: coverage.undetected_libraries,
    // Null rather than an empty list when the report carried no list at all. An
    // empty array here reads as "every language was checked and none was
    // hooked", which is the claim `runtimeHooks` refuses to make.
    runtime_coverage: coverage.runtime_coverage ?? null,
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

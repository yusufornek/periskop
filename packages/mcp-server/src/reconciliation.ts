// Why a reconciled finding exists.
//
// A reconciled finding is not read from anywhere. It is derived: the code side
// said one thing, an observation said another, and a join tied the two together
// well enough for the difference to be worth reporting. That makes it the one
// finding kind a reader cannot check by opening a file, and the whole claim rests
// on a link they cannot see.
//
// This tool shows the link. It returns the join rungs that were tried, which
// fields each rung agreed on, which sources contributed, and the difference
// itself.
//
// Two rules, the same two that shape the rest of the surface.
//
// Facts, not prose. Nothing here writes a sentence explaining a finding. Every
// value returned is a projection of something the finding already carries, and
// where the finding carries nothing the answer says so rather than filling the
// gap with a plausible reading. An explanation is the model's job; establishing
// what is true is the engine's, and a tool whose wording moves between runs
// cannot be diffed or audited.
//
// Summary first. The response is a projection and never the finding: no evidence
// bodies, no full records, one entry per contributing source rather than one per
// reference, and a join path capped by `max_depth`. What was left out is stated,
// so a short answer is never mistaken for a complete one.

import { z } from "zod";

import type { ReportSource } from "./bridge.js";
import { failure } from "./envelope.js";
import { fetchReport, type EntityRef, type Evidence, type Finding } from "./report.js";

/** Contract default for the input chain depth (mcp-tools.md section 7). */
export const DEFAULT_TRACE_DEPTH = 10;
/** Contract ceiling for the same. */
export const MAX_TRACE_DEPTH = 25;

export const traceInput = z.object({
  path: z.string().describe("Project directory the finding came from."),
  finding_id: z.string().describe("Identifier of a finding whose source is reconciled."),
  // Range checked in the handler rather than here. A schema violation would
  // throw before the tool runs, and the caller would get a validation exception
  // instead of the error envelope the contract defines for this case.
  max_depth: z
    .number()
    .int()
    .optional()
    .describe(
      `Join steps to return, 1 to ${MAX_TRACE_DEPTH}. Defaults to ${DEFAULT_TRACE_DEPTH}.`,
    ),
});

/** One rung of the join ladder, as the contract names its parts. */
export interface JoinStep {
  join: string;
  from_ref: string | null;
  to_ref: string | null;
  key_fields: string[];
  outcome: string;
}

export interface ContributingSource {
  source: string;
  detector_id: string | null;
}

export interface Discrepancy {
  kind: string;
  expected: string;
  observed: string;
}

/**
 * Which fields a join rung agreed on.
 *
 * The rungs are the engine's, and so is this mapping: it restates what each tier
 * in the reconciliation join is defined to compare. It is a lookup rather than a
 * guess, and an outcome that is not in it is reported as unrecognised instead of
 * being given a plausible key list.
 */
const KEY_FIELDS: Readonly<Record<string, string[]>> = {
  operation_and_target: ["operation", "target"],
  operation_only: ["operation"],
  target_only: ["target"],
  provider_only: ["provider_ref"],
  none: [],
};

/** Which source a reference type stands for, in the vocabulary of the contract. */
const SOURCE_OF_REF: Readonly<Record<string, string>> = {
  egress_point: "declared",
  egress_event: "observed-app",
  flow: "observed-wire",
};

const JOIN_EVIDENCE = "reconciliation_join";
const RECONCILED = "reconciled";

/**
 * Reads a key that is present on the table itself.
 *
 * A plain index reaches the prototype chain, so `KEY_FIELDS["constructor"]` and
 * `SOURCE_OF_REF["toString"]` answer with an inherited function rather than
 * nothing. Both tables are keyed by strings the engine wrote, so an outcome or a
 * reference type named after an Object member would have been treated as a
 * recognised one and its unrecognised note would never have been written.
 */
function lookup<T>(table: Readonly<Record<string, T>>, key: string): T | undefined {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}

export async function traceReconciliation(
  bridge: ReportSource,
  input: z.infer<typeof traceInput>,
): Promise<Record<string, unknown>> {
  const depth = input.max_depth ?? DEFAULT_TRACE_DEPTH;
  if (!Number.isInteger(depth) || depth < 1 || depth > MAX_TRACE_DEPTH) {
    return failure(
      "INVALID_ARGUMENT",
      `max_depth must be an integer between 1 and ${MAX_TRACE_DEPTH}, got ${depth}`,
    );
  }

  const read = await fetchReport(bridge, input.path);
  if (!read.ok) {
    // The contract's closed code table has no entry for an unreadable answer,
    // and this is the nearest true one: the engine did not give this server a
    // report. An envelope rather than the TypeError the bare cast used to throw
    // three lines below.
    return failure(
      "CORE_UNAVAILABLE",
      `the engine answered with something this server cannot read as a scan report: ${read.problem}`,
    );
  }
  const report = read.report;
  const finding = [...report.findings, ...report.suspect_findings].find(
    (candidate) => candidate.finding_id === input.finding_id,
  );

  if (!finding) {
    return failure(
      "FINDING_NOT_FOUND",
      "no finding with that identifier in the current scan; identifiers are derived from the finding itself, so rescan if the code or the observations changed",
    );
  }

  // An observation or a declaration was read from somewhere, so there is no
  // reconciliation graph under it to walk. Saying which tool does have an answer
  // is the difference between an error and a dead end.
  if (finding.source !== RECONCILED) {
    return failure(
      "TRACE_UNSUPPORTED",
      `finding ${finding.finding_id} has source ${finding.source ?? "unknown"} rather than ${RECONCILED}; only a derived finding has a reconciliation trace, and a data flow trace is what a declared or observed finding supports`,
    );
  }

  return trace(finding, depth);
}

/**
 * Projects one reconciled finding, without asking the engine anything further.
 *
 * Separate from the lookup so that the projection can be exercised directly.
 * Everything it returns comes from the finding it was handed.
 */
export function trace(finding: Finding, maxDepth: number): Record<string, unknown> {
  const notes: string[] = [];
  const refs = finding.refs ?? [];
  const evidence = finding.evidence ?? [];

  // A reconciled finding is the join of at least two records; the join is what
  // brought it into existence. So neither list can honestly be missing or empty,
  // and defaulting them to `[]` turned a loss of data into two positive claims:
  // no source contributed, and nothing was left out of this answer.
  const refsUnread = refs.length === 0;
  const evidenceUnread = evidence.length === 0;
  if (refsUnread) {
    notes.push(
      `This finding carries ${finding.refs === undefined ? "no refs field" : "an empty refs list"}, so which records it was joined from could not be read; a reconciled finding rests on at least two.`,
    );
  }
  if (evidenceUnread) {
    notes.push(
      `This finding carries ${finding.evidence === undefined ? "no evidence field" : "an empty evidence list"}, so the join path could not be read and is null rather than empty.`,
    );
  }

  const joinEvidence = evidence.filter((item) => item.evidence_type === JOIN_EVIDENCE);
  const otherEvidence = evidence.length - joinEvidence.length;
  if (otherEvidence > 0) {
    // Counted rather than dropped. Evidence of another type on a reconciled
    // finding means the engine attached something this projection does not
    // model, and hiding it would make the trace look complete.
    notes.push(
      `${otherEvidence} evidence ${plural(otherEvidence, "entry", "entries")} of another type ${plural(otherEvidence, "is", "are")} not part of the join path.`,
    );
  }

  const steps = joinEvidence.map((item) => step(item, refs, notes));
  const shown = steps.slice(0, maxDepth);
  const truncatedByDepth = steps.length > maxDepth;
  if (truncatedByDepth) {
    notes.push(
      `${steps.length - maxDepth} of ${steps.length} join steps were left out by max_depth=${maxDepth}; raise it to see the rest.`,
    );
  }

  const sources = contributingSources(finding, refs, notes);
  const found = discrepancy(finding, joinEvidence, notes);

  return {
    finding_id: finding.finding_id,
    kind: finding.kind ?? null,
    source: finding.source ?? null,
    join_path: evidenceUnread ? null : shown,
    contributing_sources: sources,
    discrepancy: found,
    truncated: truncatedByDepth,
    // Never left empty when something was left out, and never invented when
    // nothing was: a note that appears on every answer stops being read.
    coverage_note: notes.length > 0 ? notes.join(" ") : null,
  };
}

function step(item: Evidence, refs: EntityRef[], notes: string[]): JoinStep {
  const parsed = parseJoinRef(item.ref);
  if (!parsed) {
    // The rung is present but its shape is not one this projection knows. It is
    // reported as unrecognised rather than skipped, because a missing step would
    // make the join look shorter than it was.
    notes.push(`One join step could not be read and is reported as unrecognised.`);
    return {
      join: "unknown",
      from_ref: refOf(refs, "egress_point"),
      to_ref: null,
      key_fields: [],
      outcome: "unrecognised",
    };
  }

  if (parsed.unparsed.length > 0) {
    notes.push(
      `${parsed.unparsed.length} field${parsed.unparsed.length === 1 ? "" : "s"} of a join step were not in name=value form and were not read.`,
    );
  }

  const keyFields = lookup(KEY_FIELDS, parsed.outcome);
  if (!keyFields) {
    notes.push(
      `Join outcome ${parsed.outcome} is not one this server has a key list for, so its key fields are reported as empty rather than guessed.`,
    );
  }

  return {
    join: parsed.join,
    from_ref: refOf(refs, "egress_point"),
    to_ref: soleRef(refs, "egress_event", notes),
    key_fields: keyFields ?? [],
    outcome: parsed.outcome,
  };
}

interface ParsedJoin {
  join: string;
  outcome: string;
  values: Map<string, string>;
  unparsed: string[];
}

/**
 * Reads one join evidence reference.
 *
 * The engine writes these as `J<n>:<outcome>` followed by `name=value` fields.
 * Nothing is inferred from the text beyond that split; a reference that does not
 * have the shape returns nothing and the caller reports it as unrecognised.
 */
function parseJoinRef(ref: string): ParsedJoin | null {
  const tokens = ref.trim().split(/\s+/).filter(Boolean);
  const head = tokens[0];
  if (!head) return null;

  const separator = head.indexOf(":");
  if (separator < 0) return null;
  const join = head.slice(0, separator);
  const outcome = head.slice(separator + 1);
  if (!/^J[1-9][0-9]*$/.test(join) || outcome.length === 0) return null;

  const values = new Map<string, string>();
  const unparsed: string[] = [];
  for (const token of tokens.slice(1)) {
    const equals = token.indexOf("=");
    if (equals <= 0) {
      unparsed.push(token);
      continue;
    }
    values.set(token.slice(0, equals), token.slice(equals + 1));
  }

  return { join, outcome, values, unparsed };
}

function refOf(refs: EntityRef[], type: string): string | null {
  return refs.find((ref) => ref.ref_type === type)?.ref_id ?? null;
}

/**
 * The reference a step points at, when there is exactly one candidate.
 *
 * A join evidence entry names the rung and the destinations, not which
 * observation supplied them. With one observation on the finding the answer is
 * unambiguous; with several, naming one of them would be a guess, so the field is
 * null and the note says why.
 */
function soleRef(refs: EntityRef[], type: string, notes: string[]): string | null {
  const matching = refs.filter((ref) => ref.ref_type === type);
  const only = matching[0];
  if (matching.length === 1 && only) return only.ref_id;
  if (matching.length > 1) {
    notes.push(
      `The finding rests on ${matching.length} observations and a join step does not name which one it came from, so to_ref is null.`,
    );
  }
  return null;
}

/**
 * Which sources fed the finding.
 *
 * One entry per source rather than one per reference: a point called a thousand
 * times is still one declared source and one observed one, and listing every
 * reference would put the finding's whole reference list into the answer.
 *
 * Null rather than an empty list when nothing could be read. Zero contributing
 * sources is not a state a reconciled finding can be in, so an empty list here
 * would not be a fact about the finding but a report of this projection's own
 * failure, written in the words of a fact.
 */
function contributingSources(
  finding: Finding,
  refs: EntityRef[],
  notes: string[],
): ContributingSource[] | null {
  const declared = finding.data_sources;
  if (declared && declared.length > 0) {
    return declared.map((entry) => ({
      source: entry.source,
      detector_id: entry.detector_id ?? null,
    }));
  }

  const seen = new Map<string, ContributingSource>();
  const unknown = new Set<string>();
  for (const ref of refs) {
    const source = lookup(SOURCE_OF_REF, ref.ref_type);
    if (!source) {
      unknown.add(ref.ref_type);
      continue;
    }
    if (!seen.has(source)) seen.set(source, { source, detector_id: null });
  }

  if (unknown.size > 0) {
    notes.push(
      `Reference ${plural(unknown.size, "type", "types")} ${[...unknown].sort().join(", ")} ${plural(unknown.size, "is", "are")} not mapped to a source and ${plural(unknown.size, "was", "were")} left out.`,
    );
  }
  if (seen.size === 0) return null;

  // The per source detector is only carried when the finding declares
  // data_sources. Reporting the reconciliation rule id here instead would name
  // the detector that combined the sources as the one that found them.
  notes.push(
    "Per source detector ids are reported as null: this finding carries no data_sources block, so which detector produced each contribution is not recorded.",
  );
  // Ordered by code unit rather than by `localeCompare`, which sorts by the
  // machine's locale: the same report would serialise two ways on two machines
  // and every diff of two runs would carry the difference. Determinism is a
  // stated property of every answer here (CLAUDE.md).
  return [...seen.values()].sort((a, b) => (a.source < b.source ? -1 : a.source > b.source ? 1 : 0));
}

/**
 * The difference the finding is about.
 *
 * Read from the join evidence, which carries the two destinations for a drift.
 * A finding whose evidence names no pair gets null, which is the correct answer
 * for a kind such as a dormant code point: nothing was observed, so there is no
 * observed value to put opposite the declared one.
 *
 * Which is why a rung that names one side and not the other cannot be dropped in
 * silence. Dropping it produced that same null, and the null is read as the
 * dormant answer: nothing was observed. A rung carrying `observed=` and no
 * `declared=` says the opposite, and the reader was handed the reverse of what
 * the engine found.
 */
function discrepancy(finding: Finding, joinEvidence: Evidence[], notes: string[]): Discrepancy | null {
  const pairs: Discrepancy[] = [];
  let halfNamed = 0;
  for (const item of joinEvidence) {
    const parsed = parseJoinRef(item.ref);
    if (!parsed) continue;
    const expected = parsed.values.get("declared");
    const observed = parsed.values.get("observed");
    if (expected === undefined || observed === undefined) {
      // Neither side named is the dormant case and belongs to the null above.
      // One side named is a rung this projection could not turn into a pair.
      if (expected !== undefined || observed !== undefined) halfNamed += 1;
      continue;
    }
    pairs.push({
      kind: parsed.values.get("drift") ?? finding.kind ?? "unknown",
      expected,
      observed,
    });
  }

  if (halfNamed > 0) {
    notes.push(
      `${halfNamed} join ${plural(halfNamed, "step", "steps")} named one side of the difference and not the other, so ${plural(halfNamed, "it was", "they were")} not read as a difference. A null discrepancy here does not state that nothing was observed.`,
    );
  }

  const first = pairs[0];
  if (!first) return null;
  const distinct = new Set(pairs.map((pair) => `${pair.kind}|${pair.expected}|${pair.observed}`));
  if (distinct.size > 1) {
    notes.push(
      `The finding records ${distinct.size} distinct differences and the contract carries one; the first in the finding's own order is returned.`,
    );
  }
  return first;
}

function plural(count: number, one: string, many: string): string {
  return count === 1 ? one : many;
}

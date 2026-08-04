// Which sources fed the run, and what the network source contributed.
//
// Three questions about a scan cannot be answered from its findings. How many
// sources spoke. Whether a network sensor was one of them. How much traffic each
// bucket kept out of the count. All three are answered by the coverage
// statement, and this module is the only place that reads them, so there is one
// mapping from what the report says to what the server answers rather than one
// per tool.
//
// One rule shapes every function here. A field the report does not carry is
// unknown, and unknown is not the same answer as no. A server that says
// `not_running` when nothing told it either way is making a claim about the
// machine on the strength of its own ignorance, which is the substitution this
// product exists to refuse: not seeing something is not the same as it not
// being there.
//
// The values below are snake_case because ADR-006 (K-09) writes every schema
// enum that way and documents exactly two exceptions, neither of which is this
// one. They were spelled with spaces until the contract gate froze them, which
// would have made a third spelling; `runtime_coverage[].status` in
// coverage-statement.schema.json already carries the sibling `not_instrumented`,
// so a client comparing against the spelling it read there would never match.

import type { Coverage, Finding } from "./report.js";

/** A source that was there. */
export const SENSOR_RUNNING = "running";
/** A source that was not, on the report's own word. */
export const SENSOR_NOT_RUNNING = "not_running";
/**
 * Neither of the above, and deliberately a third word.
 *
 * Sharing a spelling with [`SENSOR_NOT_RUNNING`] would make the two states
 * indistinguishable to a reader, which is the failure this module is written to
 * prevent.
 */
export const UNKNOWN = "unknown";

/** Hooks were attached, on the report's own word, for at least one language. */
export const HOOKS_INSTRUMENTED = "instrumented";
/** Hooks were attached but partially, and no language is fully covered. */
export const HOOKS_DEGRADED = "degraded";
/** Every language the report named says no hook ran. */
export const HOOKS_NOT_INSTRUMENTED = "not_instrumented";

/** Modes whose source list includes the wire (coverage-statement.schema.json). */
const MODES_WITH_WIRE: ReadonlySet<string> = new Set(["full", "static_plus_wire"]);

/** Modes that name their sources and do not include the wire. */
const MODES_WITHOUT_WIRE: ReadonlySet<string> = new Set(["static_only", "static_plus_runtime"]);

/** A language whose hook was in place, whether or not it saw everything. */
const STATUS_INSTRUMENTED = "instrumented";
/** A language whose hook was in place and partial. */
const STATUS_DEGRADED = "degraded";

/**
 * Statuses that mean no hook ran for that language
 * (coverage-statement.schema.json).
 *
 * The two are kept apart in the report because one is a user choice and the
 * other is a gap in the product, and both are read here only for what they have
 * in common: nothing was hooked.
 */
const STATUSES_WITHOUT_HOOK: ReadonlySet<string> = new Set(["not_instrumented", "unsupported"]);

/** The finding kind the wire source exists to produce (finding.schema.json). */
const UNMATCHED_WIRE_TRAFFIC = "unmatched_wire_traffic";

/**
 * How many sources fed reconciliation, in the report's own vocabulary.
 *
 * A reader cannot weigh a finding without it. The same absence of evidence means
 * something different when one source spoke than when three did, and a scan that
 * only read code has nothing to say about what actually left the machine.
 *
 * An unrecognised value is passed through rather than flattened to unknown: it
 * is what the report says, and a mode this server has not been taught is still
 * information the reader can look up.
 */
export function reconciliationMode(coverage: Coverage): string {
  return coverage.reconciliation_mode ?? UNKNOWN;
}

/**
 * Whether a network sensor fed this run.
 *
 * Read from `reconciliation_mode` rather than from `sensor_platform_class`,
 * although the second field looks like the direct answer. It is not: the engine
 * writes `none` there whenever the capture mechanism does not identify a
 * platform on its own, which a pcap capture never does, so a run with a real
 * sensor behind it can carry `none`. The mode field states which sources fed
 * reconciliation and nothing else, so it is the one that can be trusted with
 * this question.
 */
export function networkSensor(coverage: Coverage): string {
  const mode = coverage.reconciliation_mode;
  if (mode === undefined) return UNKNOWN;
  if (MODES_WITH_WIRE.has(mode)) return SENSOR_RUNNING;
  if (MODES_WITHOUT_WIRE.has(mode)) return SENSOR_NOT_RUNNING;
  // A mode this server does not know may or may not include the wire. Picking
  // either answer would be a guess about the machine.
  return UNKNOWN;
}

/**
 * Whether runtime hooks fed this run.
 *
 * A boolean here was the same substitution the sensor field made, one line
 * further down. `runtime_coverage.some(status === "instrumented")` answers false
 * for a report that listed no language at all, and false was published as "the
 * hooks were not attached": a claim about the user's machine built out of a list
 * this server never received. The two runs it could not tell apart are the two a
 * reader acts on differently, since an unhooked run explains away every
 * unmatched flow it failed to match.
 *
 * So the states are the report's, not a boolean's. Absent and empty are the same
 * answer and it is unknown: an engine older than the field says nothing, and a
 * report that named no language has said nothing about hooks either. A status
 * this server has not been taught leaves the run unknown for the reason
 * `networkSensor` gives, rather than being counted as no hook.
 *
 * Degraded keeps its own word. Folded into instrumented it would claim full
 * coverage the report did not, and folded into not instrumented it would drop
 * observations that exist; per language detail stays in the coverage tool, which
 * returns `runtime_coverage` as the engine wrote it.
 */
export function runtimeHooks(coverage: Coverage): string {
  const languages = coverage.runtime_coverage;
  if (languages === undefined || languages.length === 0) return UNKNOWN;
  if (languages.some((entry) => entry.status === STATUS_INSTRUMENTED)) return HOOKS_INSTRUMENTED;
  if (languages.some((entry) => entry.status === STATUS_DEGRADED)) return HOOKS_DEGRADED;
  if (languages.every((entry) => STATUSES_WITHOUT_HOOK.has(entry.status))) {
    return HOOKS_NOT_INSTRUMENTED;
  }
  return UNKNOWN;
}

/**
 * The four counters that hold flows producing no finding, and the count they are
 * read against.
 *
 * `in_scope_flows` is not a fifth silent bucket. It holds the flows attributed to
 * the code under scan, which are the only ones derived findings come from, and it
 * is here because the others are unreadable without it.
 *
 * It is the denominator of three of them, not four. `flow_scope` partitions every
 * flow into in_scope, out_of_scope_process, known_benign and undetermined, so
 * those three plus this one account for everything the sensor saw.
 * `unclassified_flows` is counted on the separate `classification` axis and
 * overlaps them, so adding it to the other three would double count.
 */
export interface FlowBuckets {
  in_scope_flows: number | null;
  out_of_scope_flows: number | null;
  known_benign_flows: number | null;
  unattributed_flows: number | null;
  unclassified_flows: number | null;
}

/**
 * What the wire source counted and did not report as findings, over what it saw.
 *
 * Three of the four hold traffic that was deliberately left out of the finding
 * count, and the fourth holds traffic nothing could classify. A bucket that
 * keeps flows out of the count and then does not appear in the answer is a
 * silent drop (K-15), so they are returned whether or not they are zero.
 *
 * The denominator travels with them because a bucket count alone states nothing:
 * 412 flows out of scope is a rounding error against 40000 and most of the
 * traffic against 450, and the same number reads as either until the reader is
 * told which. Withheld, it leaves the caller to guess the scale of a claim.
 *
 * Null rather than zero for a field the report omits, for the same reason the
 * sensor has three states. What these numbers mean also depends on the sensor
 * state beside them: five zeros under a sensor that was not running are the
 * arithmetic of a run that never looked, not a quiet machine.
 */
export function flowBuckets(coverage: Coverage): FlowBuckets {
  return {
    in_scope_flows: coverage.in_scope_flows ?? null,
    out_of_scope_flows: coverage.out_of_scope_flows ?? null,
    known_benign_flows: coverage.known_benign_flows ?? null,
    unattributed_flows: coverage.unattributed_flows ?? null,
    unclassified_flows: coverage.unclassified_flows ?? null,
  };
}

/**
 * How many findings say data left the machine with no code that explains it.
 *
 * Counted apart from the confidence totals because it is a different axis and a
 * much stronger claim. Confirmed and suspected answer "how sure is the
 * detector"; this answers "did something leave that nobody declared", which is
 * the one finding a reader cannot reproduce by opening a file. Folded into a
 * single total it would be one line among hundreds.
 *
 * Null rather than zero when any finding does not state its kind: an engine
 * older than the field produces findings without one, and counting zero there
 * would answer "none" to a question nothing was ever asked.
 */
export function countUnmatchedWireTraffic(findings: readonly Finding[]): number | null {
  if (findings.some((finding) => finding.kind === undefined)) return null;
  return findings.filter((finding) => finding.kind === UNMATCHED_WIRE_TRAFFIC).length;
}

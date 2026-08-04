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
// unknown, and unknown is not the same answer as no. A server that says "not
// running" when nothing told it either way is making a claim about the machine
// on the strength of its own ignorance, which is the substitution this product
// exists to refuse: not seeing something is not the same as it not being there.

import type { Coverage, Finding } from "./tools.js";

/** A source that was there. */
export const SENSOR_RUNNING = "running";
/** A source that was not, on the report's own word. */
export const SENSOR_NOT_RUNNING = "not running";
/**
 * Neither of the above, and deliberately a third word.
 *
 * Sharing a spelling with [`SENSOR_NOT_RUNNING`] would make the two states
 * indistinguishable to a reader, which is the failure this module is written to
 * prevent.
 */
export const UNKNOWN = "unknown";

/** Modes whose source list includes the wire (coverage-statement.schema.json). */
const MODES_WITH_WIRE: ReadonlySet<string> = new Set(["full", "static_plus_wire"]);

/** Modes that name their sources and do not include the wire. */
const MODES_WITHOUT_WIRE: ReadonlySet<string> = new Set(["static_only", "static_plus_runtime"]);

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

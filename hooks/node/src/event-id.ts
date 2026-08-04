// The identity of an event, derived rather than counted.
//
// data-model.md section 2 fixes the formula and the serialisation:
//
//   egress_event_id = H("ee/v1" | process_identity | t_start_bucket
//                       | target_canonical | call_shape_hash?)
//
// with fields joined by U+001F, text in NFC, an absent field written as the
// empty string, blake3 as the hash and the first eight bytes as lowercase hex.
// A counter would have been simpler and wrong: the same call seen twice has to
// carry one identity, or reconciliation counts it twice.

import { blake3Short } from "./blake3";

const UNIT_SEPARATOR = "\u001f";
const DOMAIN_TAG = "ee/v1";

/** Fixed width bucket, so a call reported twice does not slide into two ids. */
const BUCKET_MILLIS = 1000;

export interface EventIdInput {
  readonly processIdentity: string;
  readonly targetCanonical: string;
  /**
   * Hash of the call shape as the static scanner computes it. A transport level
   * hook cannot produce one: it sees a socket, not the syntax tree the hash is
   * defined over. The formula marks the field optional, so it is written as the
   * empty string rather than invented.
   */
  readonly callShapeHash: string | undefined;
  readonly epochMillis: number;
}

function canonical(field: string | undefined): string {
  return field === undefined ? "" : field.normalize("NFC");
}

/**
 * Process identity as this hook can observe it.
 *
 * The contracts name the field without defining it for an in-process hook. The
 * narrowest reading that still serves its purpose is used: enough to separate
 * two processes on one machine, and nothing that would make the identity depend
 * on what the process was doing.
 */
export function processIdentity(runtime: string, pid: number): string {
  return `${runtime}/${pid}`;
}

export function targetCanonical(host: string, port: number, pathTemplate: string): string {
  return `${host.toLowerCase()}:${port}${pathTemplate}`;
}

export function egressEventId(input: EventIdInput): string {
  const bucket = Math.floor(input.epochMillis / BUCKET_MILLIS);
  const serialised = [
    DOMAIN_TAG,
    canonical(input.processIdentity),
    String(bucket),
    canonical(input.targetCanonical),
    canonical(input.callShapeHash),
  ].join(UNIT_SEPARATOR);

  return `ee_${blake3Short(Buffer.from(serialised, "utf8"))}`;
}

// The identity of an event, derived rather than counted.
//
// schemas/egress-event.schema.json states the derivation and calls it normative:
//
//   ee_ + blake3("ee/v1" | library.module | operation | target.host_id
//                | target.path_template)[:8] as lowercase hex
//
// with the fields in that order, byte 0x1F between them, and an absent field
// written as the empty string. Nothing else takes part. No clock, no pid and no
// counter, which is what lets the same call, recorded twice in two processes or
// in two runs, collapse to one identity instead of inflating a count.
//
// The reason this lives in the contract rather than in each hook: two hooks that
// derive it differently give one call two identities, and reconciliation then
// reports one call as two observations. This hook, the python hook and
// periskop-runtime-collector all produce the same bytes for the same call, and
// event-id.test.ts pins that with a vector shared across the languages.
//
// Fields are composed to NFC before they are hashed, which data-model.md section
// 2 fixes for every identity input and which periskop_core::ids applies on the
// Rust side. Unicode lets one visible string be written as several byte
// sequences, so a module or host spelled with a composed accent and the same name
// spelled with a combining one would give one call two identities. That
// divergence is silent: neither record is rejected, reconciliation simply never
// joins them, and the coverage statement has nothing to report because nothing
// failed. The fields are usually ASCII, where NFC is a no-op, but "usually" is
// not an invariant a deduplication key can rest on, and the hook cannot see which
// spelling the module that called it was written with.
//
// String.prototype.normalize is part of the language, so this costs the hook no
// dependency.

import { blake3Short } from "./blake3";

const ID_PREFIX = "ee_";
const DOMAIN_TAG = "ee/v1";

/** Unit separator, so two fields cannot be confused for one longer field. */
const FIELD_SEPARATOR = Buffer.from([0x1f]);

/** The four fields that answer "which call is this", and no others. */
export interface CallShape {
  readonly module: string;
  readonly operation: string;
  readonly hostId: string;
  /** Optional in the schema. An absent one hashes as the empty string. */
  readonly pathTemplate: string | undefined;
}

export function egressEventId(shape: CallShape): string {
  const fields = [shape.module, shape.operation, shape.hostId, shape.pathTemplate ?? ""];
  const chunks = [Buffer.from(DOMAIN_TAG, "utf8")];
  for (const field of fields) {
    chunks.push(FIELD_SEPARATOR, Buffer.from(field.normalize("NFC"), "utf8"));
  }
  return `${ID_PREFIX}${blake3Short(Buffer.concat(chunks))}`;
}

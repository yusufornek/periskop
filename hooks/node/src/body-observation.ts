// What the transport managed to see of a body, turned into a payload shape.
//
// The Node specific problem lives here. In Python a request body is usually a
// dict the hook can walk. In Node it is a stream, and a stream is read once: a
// hook that reads it to measure it has taken the bytes away from the socket and
// broken the program it was watching. So the rule is absolute, and it is why the
// schema calls byte_size_estimate an estimate rather than a measurement.
//
// Three things can be true of a body, and each has an honest answer:
//   it arrived as one buffer  parse it under a size limit, report field paths
//   it arrived as a stream    touch nothing, report the size we were told
//   it arrived in many pieces count the bytes, do not reassemble them

import { fieldPaths } from "./payload-shape";
import type { DegradedReason, PayloadShape } from "./egress-event";

export interface BodyObservation {
  /** Bytes seen on the way out, or taken from a declared content length. */
  readonly byteSize: number;
  /** The body reached the transport as a stream, so nothing was read. */
  readonly streamed: boolean;
  /** The single buffer the body arrived as, when it arrived as one. */
  readonly sample: string | Uint8Array | undefined;
}

export interface BodyDescription {
  readonly shape: PayloadShape;
  readonly degraded: readonly DegradedReason[];
}

export const EMPTY_BODY: BodyObservation = {
  byteSize: 0,
  streamed: false,
  sample: undefined,
};

function shapeOf(
  byteSize: number,
  paths: readonly string[],
  truncatedDepth: number | undefined,
): PayloadShape {
  const shape: PayloadShape = {
    field_paths: [...paths],
    byte_size_estimate: byteSize,
  };
  return truncatedDepth === undefined ? shape : { ...shape, truncated_depth: truncatedDepth };
}

function decode(sample: string | Uint8Array): string {
  return typeof sample === "string" ? sample : Buffer.from(sample).toString("utf8");
}

/**
 * Describe a body without changing it.
 *
 * The parsed value lives for the length of this call and is dropped with it. It
 * is never stored, never copied into the event, and never handed to anything
 * that could keep it.
 */
export function describeBody(
  observation: BodyObservation,
  parseLimitBytes: number,
): BodyDescription {
  if (observation.streamed) {
    // Reading it would consume it. The size, if we have one, came from a header.
    return {
      shape: shapeOf(observation.byteSize, [], undefined),
      degraded: ["streaming_body_not_measured"],
    };
  }

  if (observation.sample === undefined) {
    if (observation.byteSize === 0) {
      // No body at all. Zero here is a fact, not a gap, so nothing is declared.
      return { shape: shapeOf(0, [], undefined), degraded: [] };
    }
    // Written in pieces. Joining them back together would be the copy this hook
    // exists to avoid, so the size stands and the shape is declared missing.
    return {
      shape: shapeOf(observation.byteSize, [], 0),
      degraded: ["payload_traversal_truncated"],
    };
  }

  if (observation.byteSize > parseLimitBytes) {
    return {
      shape: shapeOf(observation.byteSize, [], 0),
      degraded: ["payload_traversal_truncated"],
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decode(observation.sample));
  } catch {
    // Not JSON: a form post, a binary upload, a protocol we do not read. The
    // event says the shape is unknown rather than saying there were no fields.
    return {
      shape: shapeOf(observation.byteSize, [], 0),
      degraded: ["payload_traversal_truncated"],
    };
  }

  const { paths, truncatedDepth } = fieldPaths(parsed);
  return {
    shape: shapeOf(observation.byteSize, paths, truncatedDepth),
    degraded: truncatedDepth === undefined ? [] : ["payload_traversal_truncated"],
  };
}

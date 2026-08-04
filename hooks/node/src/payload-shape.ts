// Field paths out, values never.
//
// This is the file the whole hook is judged on. The event schema says content
// "is not recorded and cannot be recovered from these fields", and that promise
// has to survive payloads whose authors put data in places a schema did not
// anticipate. Two of those places matter:
//
//   values  the obvious one, and the easy one: a value is never read into a path
//   keys    the one that leaks quietly. {"customers": {"a@b.com": {...}}} turns
//           every customer address into a field path unless something stops it
//
// So key handling is a reject filter, not an accept filter. Spec section 3.1
// fixes it: keys outside the schema allow list become a placeholder, and a
// pattern check runs over key strings first. The pattern check is redundant
// while the allow list stands, and it is kept anyway. The allow list is the part
// that will be widened over time as providers add fields; the leak filter is the
// part that must still hold on the day somebody widens it carelessly.
//
// Everything in this file is shared word for word with
// `hooks/python/periskop_hook/{key_policy,shape}.py`: the same allow list, the
// same reject patterns, the same depth ceiling counted from the same starting
// depth, the same sample size, and the same reading of `truncated_depth`. That
// is a requirement, not tidiness. Both hooks write into one stream, and the same
// call recorded by both derives one `egress_event_id`, so the collector keeps a
// single record and discards the other. If the two produce different shapes,
// which one reaches the report is decided by which record happened to sort
// first. `hooks/python/tests/hook-parity-vectors.json` pins them against each
// other and both test suites read it.
//
// No schema file describes this vocabulary yet, so these two copies are the
// contract between them. A request for one is filed in
// `hub/memory/interfaces.md`.

const DYNAMIC_KEY = "<dyn>";

/** Spec section 3.1 fixes six. Below it a payload is described, not traversed. */
const MAX_DEPTH = 6;

// Array elements collapse to one path, so scanning past a handful of them buys
// nothing and costs time proportional to the payload. Stopping is declared.
const MAX_ITEMS = 16;

// Ceiling on one event's field list. A payload with thousands of distinct keys
// would otherwise put its whole structure in the record.
const MAX_PATHS = 128;

// The closed set of keys a request body may carry into a field path. Every entry
// is a fixed word from a provider request schema, so no entry can be data.
const SCHEMA_KEYS: ReadonlySet<string> = new Set([
  // Request envelope, shared across chat and completion shapes.
  "model", "messages", "message", "role", "content", "prompt", "input",
  "instructions", "system", "stream", "stream_options", "temperature",
  "top_p", "top_k", "max_tokens", "max_completion_tokens",
  "max_output_tokens", "stop", "stop_sequences", "n", "seed", "user",
  "metadata", "response_format", "presence_penalty", "frequency_penalty",
  "logit_bias", "logprobs", "top_logprobs", "modalities",
  // Tool and function calling.
  "tools", "tool_choice", "tool_calls", "tool_call_id", "function",
  "functions", "function_call", "name", "description", "arguments",
  "parameters", "properties", "required", "items", "type", "enum",
  // Content parts.
  "text", "image", "image_url", "source", "media_type", "mime_type",
  "inline_data", "data", "url", "detail", "parts", "contents", "citations",
  // Embeddings and vectors.
  "encoding_format", "dimensions", "embedding", "vector", "namespace",
  "top_k_results",
  // Provider specific.
  "anthropic_version", "cache_control", "thinking", "betas",
  "generationConfig", "safetySettings", "candidateCount",
  "systemInstruction", "category", "threshold",
  // Transport level: what an HTTP client wrapper is handed by its caller.
  "json", "params", "headers", "files", "method", "timeout",
  "extra_headers", "extra_body",
]);

// Key strings that look like they carry data rather than name a field. Run over
// keys only, which is a few hundred bytes, never over the body. One entry per
// shape data takes, in the same order as the Python hook's tuple.
const LEAKY_KEY_PATTERNS: readonly RegExp[] = [
  /[^@\s]@[^@\s]+\.[A-Za-z]{2,}/, // address shaped
  /\d{4,}/, // account, card, phone runs
  /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}/, // identifier shaped
  /^[A-Za-z0-9+/=_-]{24,}$/, // token shaped
  /[\s/\\:]/, // paths, urls, free text
  /^.{65,}$/, // longer than any field name
];

export interface FieldPathResult {
  readonly paths: readonly string[];
  /** Depth at which traversal stopped, absent when it did not stop early. */
  readonly truncatedDepth: number | undefined;
}

/** True when a key string looks like it carries data rather than names a field. */
function looksLikeContent(key: string): boolean {
  if (key.length === 0) return true;
  return LEAKY_KEY_PATTERNS.some((pattern) => pattern.test(key));
}

/** Mask a key that is not part of a known request schema, or that looks like data. */
export function maskKey(key: string): string {
  if (looksLikeContent(key)) return DYNAMIC_KEY;
  return SCHEMA_KEYS.has(key) ? key : DYNAMIC_KEY;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Walk a parsed body and collect the paths of its leaves.
 *
 * Nothing that comes out of here is derived from a value: a leaf contributes its
 * position and its position only, and its type is not recorded either, because a
 * type is one more thing a reader could try to reconstruct content from.
 *
 * `truncatedDepth` is the deepest point at which the walk gave up, not the
 * shallowest. The schema explains the field as present "so a shallow record is
 * not mistaken for a small payload", and only the deepest stop answers that: a
 * body that was sampled at depth two and cut off at depth seven is at least
 * seven levels deep, and reporting two would describe it as the shallow thing it
 * is not.
 */
export function fieldPaths(body: unknown): FieldPathResult {
  const paths = new Set<string>();
  let truncatedDepth: number | undefined;

  const emit = (path: string): void => {
    if (path.length > 0) paths.add(path);
  };

  const stopAt = (depth: number): void => {
    if (truncatedDepth === undefined || depth > truncatedDepth) truncatedDepth = depth;
  };

  const walkMapping = (value: Record<string, unknown>, prefix: string, depth: number): void => {
    const keys = Object.keys(value);
    if (keys.length === 0) {
      emit(prefix);
      return;
    }
    for (const key of keys) {
      const safe = maskKey(key);
      walk(value[key], prefix.length > 0 ? `${prefix}.${safe}` : safe, depth + 1);
    }
  };

  const walkSequence = (value: readonly unknown[], prefix: string, depth: number): void => {
    const child = `${prefix}[]`;
    if (value.length === 0) {
      emit(child);
      return;
    }
    const sampled = Math.min(value.length, MAX_ITEMS);
    for (let i = 0; i < sampled; i += 1) walk(value[i], child, depth + 1);
    // Paths repeat across homogeneous elements, so sampling loses little shape.
    // The stop is still declared, at the depth the unvisited elements sit at.
    if (value.length > sampled) stopAt(depth + 1);
  };

  const walk = (value: unknown, prefix: string, depth: number): void => {
    if (paths.size >= MAX_PATHS || depth > MAX_DEPTH) {
      // The path reached so far is still recorded. Dropping it would describe a
      // deep payload as having no field at all in that branch, which reads as a
      // smaller call than the one that happened.
      emit(prefix);
      stopAt(depth);
      return;
    }
    if (Array.isArray(value)) {
      walkSequence(value, prefix, depth);
      return;
    }
    if (isPlainObject(value)) {
      walkMapping(value, prefix, depth);
      return;
    }
    // A leaf. The path is recorded; the value is not looked at.
    emit(prefix);
  };

  walk(body, "", 0);
  return { paths: [...paths].sort(), truncatedDepth };
}

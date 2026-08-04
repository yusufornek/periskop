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

const DYNAMIC_KEY = "<dyn>";

/** Spec section 3.1 fixes six. Below it a payload is described, not traversed. */
const MAX_DEPTH = 6;

// Array elements collapse to one path, so scanning past a handful of them buys
// nothing and costs time proportional to the payload. Stopping is declared.
const MAX_ARRAY_SAMPLE = 16;

// The closed set of keys a request body may carry into a field path. Every entry
// is a fixed word from a provider request schema, so no entry can be data.
const SCHEMA_KEYS: ReadonlySet<string> = new Set([
  // Shared chat and completion shapes.
  "model",
  "messages",
  "role",
  "content",
  "prompt",
  "input",
  "instructions",
  "system",
  "stream",
  "stream_options",
  "temperature",
  "top_p",
  "top_k",
  "max_tokens",
  "max_completion_tokens",
  "max_output_tokens",
  "stop",
  "stop_sequences",
  "n",
  "seed",
  "user",
  "metadata",
  "response_format",
  "presence_penalty",
  "frequency_penalty",
  "logit_bias",
  "logprobs",
  // Tool and function calling.
  "tools",
  "tool_choice",
  "tool_calls",
  "tool_call_id",
  "function",
  "functions",
  "function_call",
  "name",
  "description",
  "arguments",
  "parameters",
  "properties",
  "required",
  "items",
  "type",
  "enum",
  // Content parts.
  "text",
  "image_url",
  "source",
  "media_type",
  "data",
  "url",
  "detail",
  "parts",
  "contents",
  "inline_data",
  "mime_type",
  // Embeddings and vectors.
  "encoding_format",
  "dimensions",
  "embedding",
  "vector",
  "namespace",
  "top_k_results",
  // Anthropic and Google specifics.
  "anthropic_version",
  "cache_control",
  "thinking",
  "generationConfig",
  "safetySettings",
  "candidateCount",
  "systemInstruction",
  "category",
  "threshold",
]);

// A key string that looks like it carries data rather than names a field. Run
// over keys only, which is a few hundred bytes, never over the body.
const LEAKY_KEY = /[@\s/\\]|\d{6,}|^.{65,}$|^[A-Za-z0-9+/]{32,}={0,2}$/;

export interface FieldPathResult {
  readonly paths: readonly string[];
  /** Depth at which traversal stopped, absent when it did not stop early. */
  readonly truncatedDepth: number | undefined;
}

/** Mask a key that is not part of a known request schema, or that looks like data. */
export function maskKey(key: string): string {
  if (LEAKY_KEY.test(key)) return DYNAMIC_KEY;
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
 */
export function fieldPaths(body: unknown): FieldPathResult {
  const paths = new Set<string>();
  let truncatedDepth: number | undefined;

  const stopAt = (depth: number): void => {
    if (truncatedDepth === undefined || depth < truncatedDepth) truncatedDepth = depth;
  };

  const walk = (value: unknown, prefix: string, depth: number): void => {
    if (depth > MAX_DEPTH) {
      stopAt(depth);
      return;
    }

    if (Array.isArray(value)) {
      const arrayPrefix = `${prefix}[]`;
      if (value.length === 0) {
        paths.add(arrayPrefix);
        return;
      }
      const sampled = Math.min(value.length, MAX_ARRAY_SAMPLE);
      if (sampled < value.length) stopAt(depth);
      for (let i = 0; i < sampled; i += 1) walk(value[i], arrayPrefix, depth + 1);
      return;
    }

    if (isPlainObject(value)) {
      const keys = Object.keys(value);
      if (keys.length === 0) {
        if (prefix.length > 0) paths.add(prefix);
        return;
      }
      for (const key of keys) {
        const safe = maskKey(key);
        walk(value[key], prefix.length > 0 ? `${prefix}.${safe}` : safe, depth + 1);
      }
      return;
    }

    // A leaf. The path is recorded; the value is not looked at.
    if (prefix.length > 0) paths.add(prefix);
  };

  walk(body, "", 1);
  return { paths: [...paths].sort(), truncatedDepth };
}

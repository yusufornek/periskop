// Which provider a host belongs to, or an honest admission that we do not know.
//
// README principle 3 runs the other way round from the usual scanner: the hook
// does not look for known providers and ignore the rest. Every call out is
// recorded, and classification happens afterwards. An unclassified destination
// is written as "unknown", which the schema calls out as a value that must never
// be omitted to hide the destination. A call to an internal gateway that happens
// to be proxying a model is exactly the call this rule keeps in the record.

/** The value the schema reserves for a destination we could not classify. */
export const UNKNOWN_PROVIDER = "unknown";

const EXACT_HOSTS: ReadonlyMap<string, string> = new Map([
  ["api.openai.com", "openai"],
  ["api.anthropic.com", "anthropic"],
  ["generativelanguage.googleapis.com", "google-gemini"],
  ["api.mistral.ai", "mistral"],
  ["api.cohere.ai", "cohere"],
  ["api.cohere.com", "cohere"],
  ["api.groq.com", "groq"],
  ["api.deepseek.com", "deepseek"],
  ["api.together.xyz", "together"],
  ["openrouter.ai", "openrouter"],
]);

// Tenant or index sits in front of these, so an exact match is not enough.
const SUFFIX_HOSTS: ReadonlyArray<readonly [string, string]> = [
  [".openai.azure.com", "azure-openai"],
  [".cognitiveservices.azure.com", "azure-cognitive"],
  ["-aiplatform.googleapis.com", "google-vertex"],
  [".huggingface.co", "huggingface"],
  [".pinecone.io", "pinecone"],
  [".weaviate.network", "weaviate"],
  [".qdrant.io", "qdrant"],
];

// Region sits in the middle of these, so neither an exact nor a suffix match
// reaches them. Anchored at both ends: a suffix test alone would classify
// `bedrock-runtime.eu-west-1.amazonaws.com.attacker.test` as Bedrock.
const PATTERN_HOSTS: ReadonlyArray<readonly [RegExp, string]> = [
  [/^bedrock(-runtime)?\.[a-z0-9-]+\.amazonaws\.com$/, "aws-bedrock"],
];

/**
 * Classify a destination host.
 *
 * This table and the one in `hooks/python/periskop_hook/target.py` are identical
 * entry for entry, and have to be. Reconciliation compares a declared provider
 * against an observed one, so a table that knows `api.groq.com` in one language
 * and not in the other makes "the code says OpenAI, the wire says Groq" a
 * finding that appears in Node processes and never in Python ones. The two are
 * pinned against each other by `hooks/python/tests/hook-parity-vectors.json`.
 *
 * The table is copied into each hook rather than read from a shared data file
 * because a hook runs inside somebody else's process, where the rules directory
 * is not on disk and reading a file per request would be work the performance
 * budget does not have. There is no single source to generate it from today; a
 * request for one is filed in `hub/memory/interfaces.md`. The cost of the copy
 * is bounded either way: being wrong here writes "unknown", which loses the
 * classification and never loses the call.
 */
export function classifyHost(host: string | undefined): string {
  if (host === undefined || host.length === 0) return UNKNOWN_PROVIDER;
  const normalised = host.toLowerCase();

  const exact = EXACT_HOSTS.get(normalised);
  if (exact !== undefined) return exact;

  for (const [suffix, provider] of SUFFIX_HOSTS) {
    if (normalised.endsWith(suffix)) return provider;
  }

  for (const [pattern, provider] of PATTERN_HOSTS) {
    if (pattern.test(normalised)) return provider;
  }

  return UNKNOWN_PROVIDER;
}

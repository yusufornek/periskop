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

const SUFFIX_HOSTS: ReadonlyArray<readonly [string, string]> = [
  [".openai.azure.com", "azure-openai"],
  [".cognitiveservices.azure.com", "azure-cognitive"],
  ["-aiplatform.googleapis.com", "google-vertex"],
  [".huggingface.co", "huggingface"],
  [".pinecone.io", "pinecone"],
  [".weaviate.network", "weaviate"],
  [".qdrant.io", "qdrant"],
];

// Region sits in the middle of these, so a suffix match is not enough.
const PATTERN_HOSTS: ReadonlyArray<readonly [RegExp, string]> = [
  [/^bedrock(-runtime)?\.[a-z0-9-]+\.amazonaws\.com$/, "aws-bedrock"],
];

/**
 * Classify a destination host.
 *
 * The table is a copy of the provider signatures the network sensor spec keeps
 * in rules/providers, and copies drift. It lives here because a hook runs inside
 * somebody else's process, where the rules directory is not on disk and reading
 * a file per request would be work the performance budget does not have. The
 * cost of the copy is that a provider added to the rules is not known to the
 * hook until the hook ships again; the cost is bounded because being wrong here
 * means writing "unknown", which loses classification and never loses the call.
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

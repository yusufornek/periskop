// A raw fetch at an AWS Bedrock runtime endpoint.
//
// This fixture exists because the TypeScript rule set used to walk past it. The
// provider host alternation is copied into every language family's
// `http-literal-endpoint.toml`, and the TypeScript copy was written without the
// Bedrock alternative the Python, Go and Java copies carry. The result was the
// worst shape a detector can fail in: the call produced no finding, and because
// no module is imported it produced no `undetected_libraries` entry either, so
// the report said nothing at all about an egress that happens on every request.
//
// The region sits in the middle of the host, which is why the pattern cannot be
// an exact host or a suffix. A fixture with a hard coded region is the point:
// the pattern has to survive a real one.
export async function summarizeWithBedrock(record: string, token: string) {
  return fetch(
    "https://bedrock-runtime.eu-central-1.amazonaws.com/model/anthropic.claude-3-sonnet/invoke",
    {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify({ messages: [{ role: "user", content: record }] }),
    },
  );
}

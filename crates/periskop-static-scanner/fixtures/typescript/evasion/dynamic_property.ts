// Known gap: the method name is not in the syntax tree.
//
// Resolving `action` would mean executing the program. Runtime instrumentation
// exists as a second source precisely because of cases like this.
import OpenAI from "openai";

const client = new OpenAI();

export async function summarize(record: string, action = "create") {
  const target = (client.chat.completions as never)[action] as CallableFunction;
  return target({ model: "gpt-4", messages: [{ content: record }] });
}

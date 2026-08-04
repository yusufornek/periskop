import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();

export async function summarize(record: string) {
  return client.messages.create({
    model: "claude-3-5-sonnet",
    messages: [{ role: "user", content: record }],
  });
}
